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

CONSIDER_PORT = False

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
                if CONSIDER_PORT:
                    flow_id = '%s-%s|%s-%s,%s' % (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport, 'TCP')
                else:
                    flow_id = '%s|%s,%s' % (pkt[IP].src, pkt[IP].dst, 'TCP')
                self.flows[flow_id] = self.flows.get(flow_id, TCPFlow(pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport))
                self.flows[flow_id].add_pkt(pkt)
            elif UDP in pkt:
                if CONSIDER_PORT:
                    flow_id = '%s-%s|%s-%s,%s' % (pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport, 'UDP')
                else:
                    flow_id = '%s|%s,%s' % (pkt[IP].src, pkt[IP].dst, 'UDP')
                self.flows[flow_id] = self.flows.get(flow_id, UDPFlow(pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport))
                self.flows[flow_id].add_pkt(pkt)
            elif ICMP in pkt:
                flow_id = '%s-%s,%s' % (pkt[IP].src, pkt[IP].dst, 'ICMP')
                self.flows[flow_id] = self.flows.get(flow_id, ICMPFlow(pkt[IP].dst, pkt[IP].src))
                self.flows[flow_id].add_pkt(pkt)
            else:
                flow_id = '%s-%s,%s' % (pkt[IP].src, pkt[IP].dst, 'IP')
                self.flows[flow_id] = self.flows.get(flow_id, Flow(pkt[IP].dst, pkt[IP].src))
                self.flows[flow_id].add_pkt(pkt)

        elif pkt[IP].dst == self.ip or pkt[Ether].dst == self.mac:
            if len(self.ip) == 0:
                self.ip = pkt[IP].dst
                
            if TCP in pkt:
                if CONSIDER_PORT:
                    flow_id = '%s-%s|%s-%s,%s' % (pkt[IP].dst, pkt[TCP].dport, pkt[IP].src, pkt[TCP].sport, 'TCP')
                else:
                    flow_id = '%s|%s,%s' % (pkt[IP].dst, pkt[IP].src, 'TCP')
                self.flows[flow_id] = self.flows.get(flow_id, TCPFlow(pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport))
                self.flows[flow_id].add_pkt(pkt)
            elif UDP in pkt:
                if CONSIDER_PORT:
                    flow_id = '%s-%s|%s-%s,%s' % (pkt[IP].dst, pkt[UDP].dport, pkt[IP].src, pkt[UDP].sport, 'UDP')
                else:
                    flow_id = '%s|%s,%s' % (pkt[IP].dst, pkt[IP].src, 'UDP')
                self.flows[flow_id] = self.flows.get(flow_id, UDPFlow(pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport))
                self.flows[flow_id].add_pkt(pkt)
            elif ICMP in pkt:
                flow_id = '%s-%s,%s' % (pkt[IP].dst, pkt[IP].src, 'ICMP')
                self.flows[flow_id] = self.flows.get(flow_id, ICMPFlow(pkt[IP].src, pkt[IP].dst))
                self.flows[flow_id].add_pkt(pkt)
            else:
                flow_id = '%s-%s,%s' % (pkt[IP].dst, pkt[IP].src, 'IP')
                self.flows[flow_id] = self.flows.get(flow_id, Flow(pkt[IP].src, pkt[IP].dst))
                self.flows[flow_id].add_pkt(pkt)

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
    def __init__(self, ip_src, ip_dst):
        self.ip_src = ip_src
        self.ip_dst = ip_dst

        self.data_trans = {}
        self.ack_ts = {}
        self.src_side_rtt = []
        self.dst_side_rtt = []

    def add_pkt(self, pkt):
        ts = int(pkt.time)
        self.data_trans[ts] = self.data_trans.get(ts, [0, 0])
        if pkt[IP].src == self.ip_src:
            # 1 for sent out
            self.data_trans[ts][1] += len(pkt)
        elif pkt[IP].dst == self.ip_src:
            # 0 for received
            self.data_trans[ts][0] += len(pkt)
        self.process_rtt(pkt)

    def process_rtt(self, pkt):
        if pkt[IP].src == self.ip_src:
            self.ack_ts['last_src'] = float(pkt.time)
            if 'last_dst' in self.ack_ts:
                time_diff = 1000 * (float(pkt.time) - self.ack_ts['last_dst'])
                if time_diff < RTT_MAX:
                    self.src_side_rtt.append(time_diff)
        else:
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

class ICMPFlow(Flow):
    def __init__(self, ip_src, ip_dst):
        super().__init__(ip_src, ip_dst)

    def get_indentifier(self):
        rtt = 0
        rtt += np.average(self.src_side_rtt) if len(self.src_side_rtt) > 0 else 0
        rtt += np.average(self.dst_side_rtt) if len(self.dst_side_rtt) > 0 else 0
        return '%dms,%s<->%s,ICMP' % (rtt, self.ip_src, self.ip_dst)

class UDPFlow(Flow):
    def __init__(self, ip_src, sport, ip_dst, dport):
        super().__init__(ip_src, ip_dst)
        self.sport = sport
        self.dport = dport

    def get_indentifier(self):
        rtt = 0
        rtt += np.average(self.src_side_rtt) if len(self.src_side_rtt) > 0 else 0
        rtt += np.average(self.dst_side_rtt) if len(self.dst_side_rtt) > 0 else 0
        if CONSIDER_PORT:
            return '%dms,%s-%s<->%s-%s,UDP' % (rtt, self.ip_src, self.sport, self.ip_dst, self.dport)
        else:
            return '%dms,%s<->%s,UDP' % (rtt, self.ip_src, self.ip_dst)

class TCPFlow(Flow):
    def __init__(self, ip_src, sport, ip_dst, dport):
        super().__init__(ip_src, ip_dst)
        self.sport = sport
        self.dport = dport
        self.ack_ts = {'from_src': {}, 'from_dst': {}}

    def get_indentifier(self):
        rtt = 0
        rtt += np.average(self.src_side_rtt) if len(self.src_side_rtt) > 0 else 0
        rtt += np.average(self.dst_side_rtt) if len(self.dst_side_rtt) > 0 else 0
        if CONSIDER_PORT:
            return '%dms,%s-%s<->%s-%s,TCP' % (rtt, self.ip_src, self.sport, self.ip_dst, self.dport)
        else:
            return '%dms,%s<->%s,TCP' % (rtt, self.ip_src, self.ip_dst)
    
    def process_rtt(self, pkt):
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

        else:
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
    if len(sys.argv) < 3:
        print('Input format: python regular_trace_extract.py device_file input_file [output_file]')
        exit()
    elif len(sys.argv) == 3:
        output_file = 'output.json'
    else:
        output_file = sys.argv[3]
    device_file = sys.argv[1]
    input_files = sys.argv[2]
    input_files = input_files.split(',')

    devices = json.load(open(device_file, 'r'))
    # devices = [{"name": "AmazonEchoGen1", "ip": "192.168.0.15"}]
    Devices = {Device(**de) for de in devices}

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
                    if total_count % 10000 == 0:
                        print('%f, Packet No. %d' % (time.time(), total_count))

                    for de in Devices:
                        de.add_pkt(pkt)

    ret = {de.get_indentifier(): de.to_dict() for de in Devices}
    json.dump(ret, open(output_file, 'w'))

# python3 regular_trace_extract.py yourthing/devices.json yourthing/dataset/eth1-20180412.1405.1523559900 yourthing/processed/output.json