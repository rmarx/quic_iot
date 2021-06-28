# ----------------------- What's New ----------------------- #
# 1. Add more modes
# --------------------------- END -------------------------- #

import json
import time

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP, Ether
from scapy.all import Raw
import sys
import os
import struct
import copy
from collections import defaultdict
import hashlib
import hmac
import socket

from string import digits

import numpy as np

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

VLAN = 0x8100

RTT_MAX = 2000 #ms
LOCAL_DNS = {}
REMOVE_DIGITS = str.maketrans('', '', digits)

MODE = 'Classic' # 'PortLess', 'SubnetLess8', 'SubnetLess16', 'NSLookup', 'DomainNoDigit'

def get_mask_addr(ip_addr, subnet_len):
    ad = ip_addr.split('.')
    if subnet_len == 8:
        return '%s.%s.%s.0/8' % (ad[0], ad[1], ad[2])
    elif subnet_len == 16:
        return '%s.%s.0.0/16' % (ad[0], ad[1])
    elif subnet_len == 24:
        return '%s.0.0.0/24' % (ad[0])
    else:
        print('not support')


class Device(object):
    def __init__(self, ip='', name='', mac='', type=''):
        self.ip = ip
        self.name = name
        self.mac = mac

        self.flows = {}
        # self.start_ts = float('inf')
        # self.end_ts = 0

    def get_indentifier(self):
        return '%s-%s' % (self.name, self.ip)

    def add_pkt(self, pkt):
        if (Ether not in pkt or pkt[Ether].type == VLAN) or (IP not in pkt):
            return
        # self.start_ts = min(self.start_ts, pkt.time)
        # self.end_ts = max(self.end_ts, pkt.time)

        if pkt[IP].src == self.ip or pkt[Ether].src == self.mac:
            if len(self.ip) == 0:
                self.ip = pkt[IP].src

            if TCP in pkt:
                # For flow id, it is always (self.ip -> other.ip)
                # but when generating a new instance of flow, it is (pkt.src -> pkt.dst)
                if MODE == 'Classic':
                    flow_id = '%s-%s|%s-%s,%s' % (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport, 'TCP')
                elif MODE == 'PortLess':
                    flow_id = '%s|%s,%s' % (pkt[IP].src, pkt[IP].dst, 'TCP')
                elif MODE == 'SubnetLess8':
                    flow_id = '%s|%s,%s' % (pkt[IP].src, get_mask_addr(pkt[IP].dst, 8), 'TCP')
                elif MODE == 'SubnetLess16':
                    flow_id = '%s|%s,%s' % (pkt[IP].src, get_mask_addr(pkt[IP].dst, 16), 'TCP')
                elif MODE == 'NSLookup' or MODE == 'DomainNoDigit':
                    if pkt[IP].dst not in LOCAL_DNS:
                        try:
                            LOCAL_DNS[pkt[IP].dst] = socket.gethostbyaddr(pkt[IP].dst)[0]
                            if MODE == 'DomainNoDigit':
                                LOCAL_DNS[pkt[IP].dst] = LOCAL_DNS[pkt[IP].dst].translate(REMOVE_DIGITS)
                        except Exception as e:
                            if '192.168.' in pkt[IP].dst:
                                LOCAL_DNS[pkt[IP].dst] = pkt[IP].dst
                            else:
                                print(pkt[IP].dst, e)
                                LOCAL_DNS[pkt[IP].dst] = get_mask_addr(pkt[IP].dst, 8)
                    flow_id = '%s|%s,%s' % (pkt[IP].src, LOCAL_DNS[pkt[IP].dst], 'TCP')

                self.flows[flow_id] = self.flows.get(flow_id, TCPFlow(pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport, pkt[IP].src))
                self.flows[flow_id].add_pkt(pkt)
            elif UDP in pkt:
                if MODE == 'Classic':
                    flow_id = '%s-%s|%s-%s,%s' % (pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport, 'UDP')
                elif MODE == 'PortLess':
                    flow_id = '%s|%s,%s' % (pkt[IP].src, pkt[IP].dst, 'UDP')
                elif MODE == 'SubnetLess8':
                    flow_id = '%s|%s,%s' % (pkt[IP].src, get_mask_addr(pkt[IP].dst, 8), 'UDP')
                elif MODE == 'SubnetLess16':
                    flow_id = '%s|%s,%s' % (pkt[IP].src, get_mask_addr(pkt[IP].dst, 16), 'UDP')
                elif MODE == 'NSLookup' or MODE == 'DomainNoDigit':
                    if pkt[IP].dst not in LOCAL_DNS:
                        try:
                            LOCAL_DNS[pkt[IP].dst] = socket.gethostbyaddr(pkt[IP].dst)[0]
                            if MODE == 'DomainNoDigit':
                                LOCAL_DNS[pkt[IP].dst] = LOCAL_DNS[pkt[IP].dst].translate(REMOVE_DIGITS)
                        except Exception as e:
                            if '192.168.' in pkt[IP].dst:
                                LOCAL_DNS[pkt[IP].dst] = pkt[IP].dst
                            else:
                                print(pkt[IP].dst, e)
                                LOCAL_DNS[pkt[IP].dst] = get_mask_addr(pkt[IP].dst, 8)
                    flow_id = '%s|%s,%s' % (pkt[IP].src, LOCAL_DNS[pkt[IP].dst], 'UDP')

                self.flows[flow_id] = self.flows.get(flow_id, UDPFlow(pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport, pkt[IP].src))
                self.flows[flow_id].add_pkt(pkt)
            # elif ICMP in pkt:
            #     flow_id = '%s-%s,%s' % (pkt[IP].src, pkt[IP].dst, 'ICMP')
            #     self.flows[flow_id] = self.flows.get(flow_id, ICMPFlow(pkt[IP].dst, pkt[IP].src))
            #     self.flows[flow_id].add_pkt(pkt)
            # else:
            #     flow_id = '%s-%s,%s' % (pkt[IP].src, pkt[IP].dst, 'IP')
            #     self.flows[flow_id] = self.flows.get(flow_id, Flow(pkt[IP].dst, pkt[IP].src))
            #     self.flows[flow_id].add_pkt(pkt)

        elif pkt[IP].dst == self.ip or pkt[Ether].dst == self.mac:
            if len(self.ip) == 0:
                self.ip = pkt[IP].dst
                
            if TCP in pkt:
                if MODE == 'Classic':
                    flow_id = '%s-%s|%s-%s,%s' % (pkt[IP].dst, pkt[TCP].dport, pkt[IP].src, pkt[TCP].sport, 'TCP')
                elif MODE == 'PortLess':
                    flow_id = '%s|%s,%s' % (pkt[IP].dst, pkt[IP].src, 'TCP')
                elif MODE == 'SubnetLess8':
                    flow_id = '%s|%s,%s' % (pkt[IP].dst, get_mask_addr(pkt[IP].src, 8), 'TCP')
                elif MODE == 'SubnetLess16':
                    flow_id = '%s|%s,%s' % (pkt[IP].dst, get_mask_addr(pkt[IP].src, 16), 'TCP')
                elif MODE == 'NSLookup' or MODE == 'DomainNoDigit':
                    if pkt[IP].src not in LOCAL_DNS:
                        try:
                            LOCAL_DNS[pkt[IP].src] = socket.gethostbyaddr(pkt[IP].src)[0]
                            if MODE == 'DomainNoDigit':
                                LOCAL_DNS[pkt[IP].src] = LOCAL_DNS[pkt[IP].src].translate(REMOVE_DIGITS)
                        except Exception as e:
                            if '192.168.' in pkt[IP].src:
                                LOCAL_DNS[pkt[IP].src] = pkt[IP].src
                            else:
                                print(pkt[IP].src, e)
                                LOCAL_DNS[pkt[IP].src] = get_mask_addr(pkt[IP].src, 8)
                    flow_id = '%s|%s,%s' % (pkt[IP].dst, LOCAL_DNS[pkt[IP].src], 'TCP')

                self.flows[flow_id] = self.flows.get(flow_id, TCPFlow(pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport, pkt[IP].dst))
                self.flows[flow_id].add_pkt(pkt)
            elif UDP in pkt:
                # if MODE == 'Classic':
                #     flow_id = '%s-%s|%s-%s,%s' % (pkt[IP].dst, pkt[UDP].dport, pkt[IP].src, pkt[UDP].sport, 'UDP')
                # else:
                #     flow_id = '%s|%s,%s' % (pkt[IP].dst, pkt[IP].src, 'UDP')
                if MODE == 'Classic':
                    flow_id = '%s-%s|%s-%s,%s' % (pkt[IP].dst, pkt[UDP].dport, pkt[IP].src, pkt[UDP].sport, 'UDP')
                elif MODE == 'PortLess':
                    flow_id = '%s|%s,%s' % (pkt[IP].dst, pkt[IP].src, 'UDP')
                elif MODE == 'SubnetLess8':
                    flow_id = '%s|%s,%s' % (pkt[IP].dst, get_mask_addr(pkt[IP].src, 8), 'UDP')
                elif MODE == 'SubnetLess16':
                    flow_id = '%s|%s,%s' % (pkt[IP].dst, get_mask_addr(pkt[IP].src, 16), 'UDP')
                elif MODE == 'NSLookup' or MODE == 'DomainNoDigit':
                    if pkt[IP].src not in LOCAL_DNS:
                        try:
                            LOCAL_DNS[pkt[IP].src] = socket.gethostbyaddr(pkt[IP].src)[0]
                            if MODE == 'DomainNoDigit':
                                LOCAL_DNS[pkt[IP].src] = LOCAL_DNS[pkt[IP].src].translate(REMOVE_DIGITS)
                        except Exception as e:
                            if '192.168.' in pkt[IP].src:
                                LOCAL_DNS[pkt[IP].src] = pkt[IP].src
                            else:
                                print(pkt[IP].src, e)
                                LOCAL_DNS[pkt[IP].src] = get_mask_addr(pkt[IP].src, 8)
                    flow_id = '%s|%s,%s' % (pkt[IP].dst, LOCAL_DNS[pkt[IP].src], 'UDP')

                self.flows[flow_id] = self.flows.get(flow_id, UDPFlow(pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport, pkt[IP].dst))
                self.flows[flow_id].add_pkt(pkt)
            # elif ICMP in pkt:
            #     flow_id = '%s-%s,%s' % (pkt[IP].dst, pkt[IP].src, 'ICMP')
            #     self.flows[flow_id] = self.flows.get(flow_id, ICMPFlow(pkt[IP].src, pkt[IP].dst))
            #     self.flows[flow_id].add_pkt(pkt)
            # else:
            #     flow_id = '%s-%s,%s' % (pkt[IP].dst, pkt[IP].src, 'IP')
            #     self.flows[flow_id] = self.flows.get(flow_id, Flow(pkt[IP].src, pkt[IP].dst))
            #     self.flows[flow_id].add_pkt(pkt)

        else:
            pass

    def to_dict(self):
        # ret = {'start_ts': self.start_ts, 'end_ts': self.end_ts}
        ret = {}
        for flow in self.flows.values():
            try:
                ret[flow.get_indentifier()] = flow.to_dict()
            except Exception as e:
                print('Error!', e, flow)
        return ret


class Flow(object):
    def __init__(self, ip_src, ip_dst, local_addr):
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.local_addr = local_addr

        self.data_trans = {}
        self.ack_ts = {}
        self.src_side_rtt = []
        self.dst_side_rtt = []

    def add_pkt(self, pkt):
        ts = int(pkt.time)
        self.data_trans[ts] = self.data_trans.get(ts, [0, 0])

        if self.local_addr == self.ip_src:
            if pkt[IP].src == self.ip_src:
                # 1 for sent out
                self.data_trans[ts][1] += len(pkt)
            elif pkt[IP].dst == self.ip_src:
                # 0 for received
                self.data_trans[ts][0] += len(pkt)
        elif self.local_addr == self.ip_dst:
            if pkt[IP].dst == self.ip_dst:
                # 1 for sent out
                self.data_trans[ts][1] += len(pkt)
            elif pkt[IP].src == self.ip_dst:
                # 0 for received
                self.data_trans[ts][0] += len(pkt)
        else:
            print('!!!', self.local_addr, self.ip_src, self.ip_dst)
        # if self.local_addr == '192.168.5.14':
        #     print(self.get_indentifier())
        #     print(self.local_addr, self.local_addr == self.ip_src, self.local_addr == self.ip_dst)
        #     print(pkt[IP].src, self.ip_src, pkt[IP].src == self.ip_src, pkt[IP].dst == self.ip_src, pkt[IP].dst == self.ip_dst, pkt[IP].src == self.ip_dst)
        #     print(self.data_trans[ts])
        #     print()

        self.process_rtt(pkt)

    def process_rtt(self, pkt):
        if self.local_addr == self.ip_src:
            if pkt[IP].src == self.ip_src:
                self.ack_ts['last_src'] = float(pkt.time)
                if 'last_dst' in self.ack_ts:
                    time_diff = 1000 * (float(pkt.time) - self.ack_ts['last_dst'])
                    if time_diff < RTT_MAX:
                        self.src_side_rtt.append(time_diff)
            elif pkt[IP].dst == self.ip_src:
                self.ack_ts['last_dst'] = float(pkt.time)
                if 'last_src' in self.ack_ts:
                    time_diff = 1000 * (float(pkt.time) - self.ack_ts['last_src'])
                    if time_diff < RTT_MAX:
                        self.dst_side_rtt.append(time_diff)
        else:
            if pkt[IP].dst == self.ip_dst:
                self.ack_ts['last_src'] = float(pkt.time)
                if 'last_dst' in self.ack_ts:
                    time_diff = 1000 * (float(pkt.time) - self.ack_ts['last_dst'])
                    if time_diff < RTT_MAX:
                        self.src_side_rtt.append(time_diff)
            elif pkt[IP].src == self.ip_dst:
                self.ack_ts['last_dst'] = float(pkt.time)
                if 'last_src' in self.ack_ts:
                    time_diff = 1000 * (float(pkt.time) - self.ack_ts['last_src'])
                    if time_diff < RTT_MAX:
                        self.dst_side_rtt.append(time_diff)

    def get_indentifier(self):
        rtt = 0
        rtt += np.average(self.src_side_rtt) if len(self.src_side_rtt) > 0 else 0
        rtt += np.average(self.dst_side_rtt) if len(self.dst_side_rtt) > 0 else 0
        return '%dms,%s<->%s,IP' % (rtt, self.ip_src, self.ip_dst)

    def to_dict(self):
        return self.data_trans


class UDPFlow(Flow):
    def __init__(self, ip_src, sport, ip_dst, dport, local_addr):
        super().__init__(ip_src, ip_dst, local_addr)
        self.sport = sport
        self.dport = dport

    def get_indentifier(self):
        rtt = 0
        rtt += np.average(self.src_side_rtt) if len(self.src_side_rtt) > 0 else 0
        rtt += np.average(self.dst_side_rtt) if len(self.dst_side_rtt) > 0 else 0
        if self.local_addr == self.ip_src:
            if MODE == 'Classic':
                return '%dms,%s-%s<->%s-%s,UDP' % (rtt, self.ip_src, self.sport, self.ip_dst, self.dport)
            elif MODE == 'PortLess':
                return '%dms,%s<->%s,UDP' % (rtt, self.ip_src, self.ip_dst)
            elif MODE == 'SubnetLess8':
                return '%dms,%s<->%s,UDP' % (rtt, self.ip_src, get_mask_addr(self.ip_dst, 8))
            elif MODE == 'SubnetLess16':
                return '%dms,%s<->%s,UDP' % (rtt, self.ip_src, get_mask_addr(self.ip_dst, 16))
            elif MODE == 'NSLookup':
                return '%dms,%s<->%s,UDP' % (rtt, self.ip_src, LOCAL_DNS[self.ip_dst])
            elif MODE =='DomainNoDigit':
                return '%dms,%s<->%s,UDP' % (rtt, self.ip_src, LOCAL_DNS[self.ip_dst])
        else:
            if MODE == 'Classic':
                return '%dms,%s-%s<->%s-%s,UDP' % (rtt, self.ip_src, self.sport, self.ip_dst, self.dport)
            elif MODE == 'PortLess':
                return '%dms,%s<->%s,UDP' % (rtt, self.ip_src, self.ip_dst)
            elif MODE == 'SubnetLess8':
                return '%dms,%s<->%s,UDP' % (rtt, get_mask_addr(self.ip_src, 8), self.ip_dst)
            elif MODE == 'SubnetLess16':
                return '%dms,%s<->%s,UDP' % (rtt, get_mask_addr(self.ip_src, 16), self.ip_dst)
            elif MODE == 'NSLookup':
                return '%dms,%s<->%s,UDP' % (rtt, LOCAL_DNS[self.ip_src], self.ip_dst)
            elif MODE =='DomainNoDigit':
                return '%dms,%s<->%s,UDP' % (rtt, LOCAL_DNS[self.ip_src], self.ip_dst)


class TCPFlow(Flow):
    def __init__(self, ip_src, sport, ip_dst, dport, local_addr):
        super().__init__(ip_src, ip_dst, local_addr)
        self.sport = sport
        self.dport = dport
        self.ack_ts = {'from_src': {}, 'from_dst': {}}

    def get_indentifier(self):
        rtt = 0
        rtt += np.average(self.src_side_rtt) if len(self.src_side_rtt) > 0 else 0
        rtt += np.average(self.dst_side_rtt) if len(self.dst_side_rtt) > 0 else 0
        if self.local_addr == self.ip_src:
            if MODE == 'Classic':
                return '%dms,%s-%s<->%s-%s,TCP' % (rtt, self.ip_src, self.sport, self.ip_dst, self.dport)
            elif MODE == 'PortLess':
                return '%dms,%s<->%s,TCP' % (rtt, self.ip_src, self.ip_dst)
            elif MODE == 'SubnetLess8':
                return '%dms,%s<->%s,TCP' % (rtt, self.ip_src, get_mask_addr(self.ip_dst, 8))
            elif MODE == 'SubnetLess16':
                return '%dms,%s<->%s,TCP' % (rtt, self.ip_src, get_mask_addr(self.ip_dst, 16))
            elif MODE == 'NSLookup':
                return '%dms,%s<->%s,TCP' % (rtt, self.ip_src, LOCAL_DNS[self.ip_dst])
            elif MODE =='DomainNoDigit':
                return '%dms,%s<->%s,TCP' % (rtt, self.ip_src, LOCAL_DNS[self.ip_dst])
        else:
            if MODE == 'Classic':
                return '%dms,%s-%s<->%s-%s,TCP' % (rtt, self.ip_src, self.sport, self.ip_dst, self.dport)
            elif MODE == 'PortLess':
                return '%dms,%s<->%s,TCP' % (rtt, self.ip_src, self.ip_dst)
            elif MODE == 'SubnetLess8':
                return '%dms,%s<->%s,TCP' % (rtt, get_mask_addr(self.ip_src, 8), self.ip_dst)
            elif MODE == 'SubnetLess16':
                return '%dms,%s<->%s,TCP' % (rtt, get_mask_addr(self.ip_src, 16), self.ip_dst)
            elif MODE == 'NSLookup':
                return '%dms,%s<->%s,TCP' % (rtt, LOCAL_DNS[self.ip_src], self.ip_dst)
            elif MODE =='DomainNoDigit':
                return '%dms,%s<->%s,TCP' % (rtt, LOCAL_DNS[self.ip_src], self.ip_dst)
    
    def process_rtt(self, pkt):
        if self.local_addr == self.ip_src:
            if pkt[IP].src == self.ip_src:
                syn_pkt = 1 if pkt[TCP].flags & SYN else 0
                fin_pkt = 1 if pkt[TCP].flags & FIN else 0
                next_ack = pkt[TCP].seq + len(pkt[TCP].payload) + syn_pkt + fin_pkt
                self.ack_ts['from_dst'][next_ack] = float(pkt.time)

                if pkt[TCP].ack in self.ack_ts['from_src']:
                    time_diff = 1000 * (float(pkt.time) - self.ack_ts['from_src'][pkt[TCP].ack])
                    del self.ack_ts['from_src'][pkt[TCP].ack]
                    if time_diff < RTT_MAX:
                        self.src_side_rtt.append(time_diff)

            elif pkt[IP].dst == self.ip_src:
                syn_pkt = 1 if pkt[TCP].flags & SYN else 0
                fin_pkt = 1 if pkt[TCP].flags & FIN else 0
                next_ack = pkt[TCP].seq + len(pkt[TCP].payload) + syn_pkt + fin_pkt
                self.ack_ts['from_src'][next_ack] = float(pkt.time)

                if pkt[TCP].ack in self.ack_ts['from_dst']:
                    time_diff = 1000 * (float(pkt.time) - self.ack_ts['from_dst'][pkt[TCP].ack])
                    del self.ack_ts['from_dst'][pkt[TCP].ack]
                    if time_diff < RTT_MAX:
                        self.dst_side_rtt.append(time_diff)
        
        else:
            if pkt[IP].dst == self.ip_dst:
                syn_pkt = 1 if pkt[TCP].flags & SYN else 0
                fin_pkt = 1 if pkt[TCP].flags & FIN else 0
                next_ack = pkt[TCP].seq + len(pkt[TCP].payload) + syn_pkt + fin_pkt
                self.ack_ts['from_dst'][next_ack] = float(pkt.time)

                if pkt[TCP].ack in self.ack_ts['from_src']:
                    time_diff = 1000 * (float(pkt.time) - self.ack_ts['from_src'][pkt[TCP].ack])
                    del self.ack_ts['from_src'][pkt[TCP].ack]
                    if time_diff < RTT_MAX:
                        self.src_side_rtt.append(time_diff)

            elif pkt[IP].src == self.ip_dst:
                syn_pkt = 1 if pkt[TCP].flags & SYN else 0
                fin_pkt = 1 if pkt[TCP].flags & FIN else 0
                next_ack = pkt[TCP].seq + len(pkt[TCP].payload) + syn_pkt + fin_pkt
                self.ack_ts['from_src'][next_ack] = float(pkt.time)

                if pkt[TCP].ack in self.ack_ts['from_dst']:
                    time_diff = 1000 * (float(pkt.time) - self.ack_ts['from_dst'][pkt[TCP].ack])
                    del self.ack_ts['from_dst'][pkt[TCP].ack]
                    if time_diff < RTT_MAX:
                        self.dst_side_rtt.append(time_diff)
        
        # if self.ip_dst == '93.184.216.34':
        #     print('process rtt', pkt[IP].src == self.ip_src, pkt[TCP].seq, pkt[TCP].ack, len(pkt[TCP].payload), pkt[TCP].seq+len(pkt[TCP].payload))
        #     print(int(pkt[TCP].flags & SYN), int(pkt[TCP].flags & FIN), int(pkt[TCP].flags & ACK))
        #     print(self.ack_ts)
        #     print('src_side_rtt', self.src_side_rtt)
        #     print('dst_side_rtt', self.dst_side_rtt)
        #     print()


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print('Input format: python regular_trace_extract.py with_port(True/False) device_file input_file [output_file]')
        exit()
    elif len(sys.argv) == 4:
        output_file = 'output.json'
    else:
        output_file = sys.argv[4]

    if MODE not in ['Classic', 'PortLess', 'SubnetLess8', 'SubnetLess16', 'NSLookup', 'DomainNoDigit']:
        print("mode must be one of the following: ['Classic', 'PortLess', 'SubnetLess8', 'SubnetLess16', 'NSLookup', 'DomainNoDigit']")
    MODE = sys.argv[1]
    device_file = sys.argv[2]
    input_files = sys.argv[3]
    input_files = input_files.split(',')

    devices = json.load(open(device_file, 'r'))
    # devices = [{"name": "AmazonEchoGen1", "ip": "192.168.0.15"}]
    Devices = {Device(**de) for de in devices}
    # try:
    #     LOCAL_DNS = json.load(open('local_dns.json', 'r'))
    # except:
    #     print('No local dns file found')

    total_count = 0
    for infile in input_files:
        targets = []
        if os.path.isdir(infile):
            targets = [os.path.join(infile, x) for x in sorted(os.listdir(infile))]
        else:
            targets = [infile]
        for target in targets:
            print('Processing %s' % target)
            with PcapReader(target) as pcap_reader:
                for pkt in pcap_reader:
                    total_count += 1
                    if total_count % 20000 == 0:
                        print('%f, Packet No. %d' % (time.time(), total_count))

                    # if total_count <= 10000:
                    #     continue 
                    # if total_count >= 80000:
                    #     break

                    for de in Devices:
                        de.add_pkt(pkt)

    ret = {de.get_indentifier(): de.to_dict() for de in Devices}
    json.dump(ret, open(output_file, 'w'))
    
    # json.dump(LOCAL_DNS, open('local_dns.json', 'w'))

# python3 regular_trace_extract.py yourthing/devices.json yourthing/dataset/eth1-20180412.1405.1523559900 yourthing/processed/output.json