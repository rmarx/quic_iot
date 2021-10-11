import json
import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP, Ether
import scapy.all as sc
sc.load_layer("tls")
import sys
import os
import struct
import copy
from collections import defaultdict
import hashlib
import hmac
import socket
import csv

from string import digits
from datetime import datetime

# from utils import MAX_INTERVAL_ERROR, MAX_PKTLEN_ERROR, PROCESSING_INTERVAL_LONG, PROCESSING_INTERVAL_SHORT, SHORT_PKT_THRES 
import fiat_module.utils as utils
from fiat_module.feature_selection import extract_feature_short, extract_feature_long

import numpy as np
import joblib

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
# MEANINGFUL_FLAG = 0xff
MEANINGFUL_FLAG = FIN | SYN | RST


VLAN = 0x8100

RTT_MAX = 2000 #ms
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


def convert_ts(ts):
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

PPP = ''
class Flow(object):
    def __init__(self, ip_src, ip_dst, local_addr, proto):
        self.ip_src = ip_src # not neccessarily ip address
        self.ip_dst = ip_dst
        self.local_addr = local_addr
        self.proto = proto

        self.control_candidates = [] # [(interval, pkt size)]
        self.unexpected_pkt = {}
        self.control_confirmed = []

        self.first_pkt_ts = 0
        self.last_pkt_ts = 0
        self.last_confirmed_pkt_ts = {}
        self.last_pkt_data = 0
        self.unexpected_count = 0
        self.control_count = 0
        self.is_control = False
        self.has_processed = False
        self.last_interval = 0
        self.last_confirmed_interval = 0

    def control_match(self, pkt, interval, pkt_len, pkt_flag, count=True, during_manual=False, debug=False):
        # count is to avoid double counting
        global PPP

        # time_allowance = max(interval * 0.1, utils.MAX_INTERVAL_ERROR )
        if not during_manual:
            for control_item in self.control_candidates:
                # print('control_match', np.absolute(control_item[0] - interval), control_item[1] / pkt_len)
                if (np.absolute(control_item[0] - interval) <= utils.MAX_INTERVAL_ERROR 
                    and 1-utils.MAX_PKTLEN_ERROR <= control_item[1] / pkt_len <= 1.0/(1-utils.MAX_PKTLEN_ERROR)
                    and control_item[2] == pkt_flag):
                    self.control_confirmed.append(control_item)
                    self.control_candidates.remove(control_item)
                    self.unexpected_pkt.pop(str(control_item))
                    control_item[0], control_item[1], control_item[3] = interval, pkt_len, float(pkt.time)
                    if count:
                        self.control_count += 1
                        self.unexpected_count -= 1
                    self.last_confirmed_pkt_ts[pkt_len] = float(pkt.time)
                    if debug:
                        print('is control - new!', count, (interval, pkt_len, pkt_flag), control_item)
                    return True
                elif (float(pkt.time) - control_item[3] > utils.MAX_REGULAR_INTERVAL):
                    # print('remove candidate', self.ip_src, self.ip_dst, self.proto, control_item)
                    self.control_candidates.remove(control_item)

        for control_item in self.control_confirmed:
            if (np.absolute(control_item[0] - interval) <= utils.MAX_INTERVAL_ERROR 
                and 1-utils.MAX_PKTLEN_ERROR <= control_item[1] / pkt_len <= 1.0/(1-utils.MAX_PKTLEN_ERROR)
                and control_item[2] == pkt_flag):
                # control_item[0], control_item[1] = interval, pkt_len
                # control_item[0] = 0.25 * interval + 0.75 * control_item[0]
                # control_item[1] = 0.25 * pkt_len + 0.75 * control_item[1]
                control_item[3] = float(pkt.time)
                if count:
                    self.control_count += 1
                self.last_confirmed_pkt_ts[pkt_len] = float(pkt.time)
                if debug:
                    print('is control - confirmed!', PPP, count, (interval, pkt_len, int(pkt_flag)), control_item)
                    print(control_item[1] / pkt_len, 1-utils.MAX_PKTLEN_ERROR, 1.0/(1-utils.MAX_PKTLEN_ERROR))
                return True
            elif (float(pkt.time) - control_item[3] > utils.MAX_REGULAR_INTERVAL):
                # print('remove confirmed', self.ip_src, self.ip_dst, self.proto, control_item)
                self.control_confirmed.remove(control_item)

        if count and (not during_manual):
            if interval <= utils.MAX_REGULAR_INTERVAL:
                self.control_candidates.append([interval, pkt_len, int(pkt_flag), float(pkt.time)])
                if debug:# or pkt_len==-230:
                    print('add control candidate', PPP, str([interval, pkt_len, int(pkt_flag), float(pkt.time)]))
            self.unexpected_pkt[str([interval, pkt_len, int(pkt_flag), float(pkt.time)])] = pkt
            self.unexpected_count += 1
        return False

    def get_last_confirmed_ts(self, pkt_len, ts_now):
        best_candidate_ts, pkt_len_diff = None, None
        if pkt_len in self.last_confirmed_pkt_ts:
            if ts_now - self.last_confirmed_pkt_ts[pkt_len] > utils.MAX_REGULAR_INTERVAL:
                self.last_confirmed_pkt_ts.pop(pkt_len)
            else:
                return ts_now - self.last_confirmed_pkt_ts[pkt_len]
        
        to_be_removed = []
        for candidate_len in self.last_confirmed_pkt_ts:
            if ts_now - self.last_confirmed_pkt_ts[candidate_len] > utils.MAX_REGULAR_INTERVAL:
                to_be_removed.append(candidate_len)
                continue
            if 1-utils.MAX_PKTLEN_ERROR <= pkt_len / candidate_len <= 1.0/(1-utils.MAX_PKTLEN_ERROR):
                if (best_candidate_ts is None) or (pkt_len / candidate_len < pkt_len_diff):
                    best_candidate_ts = self.last_confirmed_pkt_ts[candidate_len]
                    pkt_len_diff = pkt_len / candidate_len
        
        # clean out-dated records
        for tbr in to_be_removed: 
            self.last_confirmed_pkt_ts.pop(tbr)

        if best_candidate_ts:
            return ts_now - best_candidate_ts
        else:
            return best_candidate_ts

    def new_pkt(self, pkt, debug=False, during_manual=False):
        ret = False
        # if TCP in pkt and len(pkt[TCP].payload) == 0:
        #     ret True
        #     return ret

        ts = float(pkt.time)
        if self.first_pkt_ts == 0:
            self.first_pkt_ts = ts
        self.last_interval = ts - self.last_pkt_ts
        self.last_pkt_ts = ts

        pkt_len = -len(pkt) if pkt[IP].src == self.ip_src else len(pkt)
        self.last_pkt_data = pkt_len

        pkt_flag = 0
        if TCP in pkt:
            pkt_flag = int(pkt[TCP].flags) & MEANINGFUL_FLAG

        if during_manual:
            print('during manual, do not register new candidates')
        ret = self.control_match(pkt, self.last_interval, pkt_len, pkt_flag, during_manual=during_manual, debug=debug)
        if ret is True:
            return ret

        self.last_confirmed_interval = self.get_last_confirmed_ts(pkt_len, self.last_pkt_ts)
        if (self.last_confirmed_interval is not None) and (self.last_interval != self.last_confirmed_interval):
            ret = self.control_match(pkt, self.last_confirmed_interval, pkt_len, pkt_flag, count=False, during_manual=during_manual, debug=debug)

        if debug:
                print('last_interval', pkt_len, self.last_pkt_ts, self.last_confirmed_interval, self.last_interval, self.last_interval != self.last_confirmed_interval)
                print(ret, self.last_confirmed_pkt_ts)
        return ret

    def is_burst(self):
        return (self.last_interval < 1.0) and (self.last_pkt_ts - self.first_pkt_ts < utils.PROCESSING_INTERVAL_LONG)



class Device(object):
    def __init__(self, ip='', name='', mac='', type='', manual_log='', automated_log='', clf=None):
        self.ip = ip
        self.name = name
        self.mac = mac
        self.type = type
        self.flow_dict = {}

        self.manual_intervals = []
        if manual_log:
            self.manual_intervals = self.get_interval_from_file(manual_log)
        self.automated_intervals = []
        if automated_log:
            self.automated_intervals = self.get_interval_from_file(automated_log)
        print(self.ip, self.name, manual_log, self.manual_intervals)

        self.last_ts = 0
        self.last_ts_unexpected_short = 0
        self.unexpected_queue_short = []
        self.unexpected_queue_short_pktid = []
        self.last_ts_unexpected_long = 0
        self.unexpected_queue_long = []
        self.unexpected_queue_long_pktid = []

        self.curr_pktid = ("", 0)

        self.short_features = []
        self.long_features = []

        # for actual deployment
        self.queue_label = 0
        self.clf = clf
        self.scalar = clf
        if clf:
            self.scalar = joblib.load(self.scalar + '.scalar')
            self.clf = joblib.load(self.clf)
            

    def get_interval_from_file(self, filename):
        result_intervals = []
        with open(filename, 'r') as fp:
            csvreader = csv.reader(fp)
            a = next(csvreader)
            for line in csvreader:
                ips = json.loads(line[3])
                if self.ip in ips:
                    result_intervals.append([float(line[1]), float(line[2])])
        return result_intervals

    def identify_label(self, start_ts, end_ts, remove=True):
        label = 0
        to_remove = None
        for automated in self.automated_intervals:
            if start_ts >= automated[0] and end_ts <= automated[1]:
                label = 1
        for manual in self.manual_intervals:
            if start_ts >= manual[0] and end_ts <= manual[1]:
                label = 2
                to_remove = manual
        if remove and to_remove:
            self.manual_intervals.remove(to_remove)
        return label

    def get_flow_id(self, pkt):
        proto, sport, dport = None, None, None
        if TCP in pkt:
            proto = 'TCP'
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            try:
                if TLS in pkt:
                    proto += '+TLS%d' % (pkt[TLS].version)
                elif TLS in TLS(bytes(pkt[TCP].payload)):
                    proto += '+TLS%d' % (TLS(bytes(pkt[TCP].payload)).version)
            except Exception as e:
                print('proto error!', e)#, pkt)
        elif UDP in pkt:
            proto = 'UDP'
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            try:
                if TLS in pkt:
                    proto += '+TLS%d' % (pkt[TLS].version)
                elif TLS in TLS(bytes(pkt[UDP].payload)):
                    proto += '+TLS%d' % (TLS(bytes(pkt[UDP].payload)).version)
            except Exception as e:
                print('proto error!', e)#, pkt)
        else:
            return None

        if pkt[IP].src == self.ip or pkt[Ether].src == self.mac:
            if len(self.ip) == 0:
                self.ip = pkt[IP].src

            # For flow id, it is always (self.ip -> other.ip)
            # but when generating a new instance of flow, it is (pkt.src -> pkt.dst)
            if MODE == 'Classic':
                flow_id = '%s-%s|%s-%s,%s' % (pkt[IP].src, sport, pkt[IP].dst, dport, proto)
            elif MODE == 'PortLess':
                flow_id = '%s|%s,%s' % (pkt[IP].src, pkt[IP].dst, proto)
            elif MODE == 'SubnetLess8':
                flow_id = '%s|%s,%s' % (pkt[IP].src, get_mask_addr(pkt[IP].dst, 8), proto)
            elif MODE == 'SubnetLess16':
                flow_id = '%s|%s,%s' % (pkt[IP].src, get_mask_addr(pkt[IP].dst, 16), proto)
            elif MODE == 'NSLookup' or MODE == 'DomainNoDigit':
                if pkt[IP].dst not in utils.LOCAL_DNS:
                    try:
                        utils.LOCAL_DNS[pkt[IP].dst] = socket.gethostbyaddr(pkt[IP].dst)[0]
                        if MODE == 'DomainNoDigit':
                            utils.LOCAL_DNS[pkt[IP].dst] = utils.LOCAL_DNS[pkt[IP].dst].translate(REMOVE_DIGITS)
                    except Exception as e:
                        if '192.168.' in pkt[IP].dst:
                            utils.LOCAL_DNS[pkt[IP].dst] = pkt[IP].dst
                        else:
                            # print(pkt[IP].dst, e)
                            utils.LOCAL_DNS[pkt[IP].dst] = get_mask_addr(pkt[IP].dst, 8)
                flow_id = '%s|%s,%s' % (pkt[IP].src, utils.LOCAL_DNS[pkt[IP].dst], proto)
            return flow_id

        elif pkt[IP].dst == self.ip or pkt[Ether].dst == self.mac:
            if len(self.ip) == 0:
                self.ip = pkt[IP].dst
            
            if MODE == 'Classic':
                flow_id = '%s-%s|%s-%s,%s' % (pkt[IP].dst, dport, pkt[IP].src, sport, proto)
            elif MODE == 'PortLess':
                flow_id = '%s|%s,%s' % (pkt[IP].dst, pkt[IP].src, proto)
            elif MODE == 'SubnetLess8':
                flow_id = '%s|%s,%s' % (pkt[IP].dst, get_mask_addr(pkt[IP].src, 8), proto)
            elif MODE == 'SubnetLess16':
                flow_id = '%s|%s,%s' % (pkt[IP].dst, get_mask_addr(pkt[IP].src, 16), proto)
            elif MODE == 'NSLookup' or MODE == 'DomainNoDigit':
                if pkt[IP].src not in utils.LOCAL_DNS:
                    try:
                        utils.LOCAL_DNS[pkt[IP].src] = socket.gethostbyaddr(pkt[IP].src)[0]
                        if MODE == 'DomainNoDigit':
                            utils.LOCAL_DNS[pkt[IP].src] = utils.LOCAL_DNS[pkt[IP].src].translate(REMOVE_DIGITS)
                    except Exception as e:
                        if '192.168.' in pkt[IP].src:
                            utils.LOCAL_DNS[pkt[IP].src] = pkt[IP].src
                        else:
                            print(pkt[IP].src, e)
                            utils.LOCAL_DNS[pkt[IP].src] = get_mask_addr(pkt[IP].src, 8)
                flow_id = '%s|%s,%s' % (pkt[IP].dst, utils.LOCAL_DNS[pkt[IP].src], proto)
            return flow_id

        else:
            return None

    def new_pkt(self, pkt, pkt_id, filter_inout=None, IP_filter=[]):
        ret = 0

        self.curr_pktid = pkt_id
        global PPP
        PPP = pkt_id
        self.last_ts = float(pkt.time)
        flow_id = self.get_flow_id(pkt)

        if flow_id:
            if filter_inout == 'in' and flow_id in IP_filter:
                return ret
            else:
                proto = flow_id.split(',')[-1]
                self.flow_dict[flow_id] = self.flow_dict.get(flow_id, Flow(pkt[IP].src, pkt[IP].dst, self.ip, proto))
                
                debug = False
                # if 6388 <= pkt_id[1] <= 6388: #or 5679 <= pkt_id[1] <= 5681:
                #     debug = True

                during_manual = self.queue_label == 2
                is_control = self.flow_dict[flow_id].new_pkt(pkt, debug=debug, during_manual=during_manual)
                is_burst = self.flow_dict[flow_id].is_burst()
                
                ret = self.process_queue_long(pkt, is_control, is_burst)
                
                if filter_inout == 'out' and flow_id not in IP_filter:
                    IP_filter.append(flow_id)
                    
        return ret

    def merge_pktid(self):
        # print('before merge', self.unexpected_queue_long_pktid)
        merged_pktids = []
        last_fn = {'ids': [], 'fn': None}
        for pkt_id in self.unexpected_queue_long_pktid:
            if last_fn['fn'] is None:
                last_fn['fn'] = pkt_id[0]
            
            if last_fn['fn'] == pkt_id[0]:
                last_fn['ids'].append(pkt_id[1])
            else:
                merged_pktids.append(last_fn)
                last_fn = {'ids': [], 'fn': None}
        if last_fn['fn'] is not None:
            merged_pktids.append(last_fn)
        self.unexpected_queue_long_pktid = merged_pktids
        # print('after merge', self.unexpected_queue_long_pktid)

    def process_queue_long(self, pkt, is_control, is_burst):
        ret = 0 
        
        # each packet is processed first, here we assume that
        # there cannot be two unpredictable packets with interval more than 5 seconds
        # without any predictable packets in between
        is_unpredictable = ((not is_control) or (is_control and is_burst))
        if is_unpredictable:
            self.unexpected_queue_long.append(pkt)
            self.unexpected_queue_long_pktid.append(self.curr_pktid)
            ret = self.queue_label

        if (len(self.unexpected_queue_long) == 0 
            or self.last_ts - self.unexpected_queue_long[-1].time < utils.PROCESSING_INTERVAL_LONG):
            if is_unpredictable and len(self.unexpected_queue_long) == 5:
                self.analyze_short()
                ret = self.queue_label
            return ret
        else:
            if len(self.unexpected_queue_long) <= 1:
                self.unexpected_queue_long = []
                self.unexpected_queue_long_pktid = []
                return ret
        
        #self.merge_pktid()
        self.analyze_long()

        self.last_ts_unexpected_long = self.unexpected_queue_long[-1].time #self.last_ts
        self.unexpected_queue_long = []
        self.unexpected_queue_long_pktid = []
        self.queue_label = 0
        return ret

    def analyze_short(self):
        features = extract_feature_short(self.unexpected_queue_long[:5], self.ip)

        if self.clf:
            print('features', features)
            X = np.array(features).reshape(1, -1)
            #print('X', X)
            X_scaled = self.scalar.transform(X)
            self.queue_label = self.clf.predict(X_scaled)[0]
        else:
            self.queue_label = 0
        if self.unexpected_queue_long_pktid[0] > 100:
            self.queue_label = 2
        print('%s: analyze short %s -> current unpredictable queue is %d' % (
            self.name, 
            str([d for d in self.unexpected_queue_long_pktid[:5]]),
            self.queue_label
        ))

        features.append(self.queue_label)
        self.short_features.append({
            "name": convert_ts(self.unexpected_queue_long[0].time),
            "start_ts": float(self.unexpected_queue_long[0].time),
            "pkt_ids": self.unexpected_queue_long_pktid[:5],
            "features": features
        })

    def analyze_long(self):
        features = extract_feature_long(self.unexpected_queue_long, self.ip)
        # features.append(0) # label
        if len(self.unexpected_queue_long) > 20:
            label = self.identify_label(self.unexpected_queue_long[0].time, self.unexpected_queue_long[20].time, remove=True)
        else:
            label = self.identify_label(self.unexpected_queue_long[0].time, self.unexpected_queue_long[-1].time, remove=True)
        features.append(label)
        # features = [0]
        # print('long features', len(features), features)
        print('current unpredictable event ends', self.unexpected_queue_long_pktid)
        self.long_features.append({
            "name": convert_ts(self.unexpected_queue_long[0].time),
            "start_ts": float(self.unexpected_queue_long[0].time),
            "pkt_ids": self.unexpected_queue_long_pktid,
            "features": features
        })

    
    def get_short_features(self):
        return self.short_features

    def get_long_features(self):
        return self.long_features


class Predictor(object):
    def __init__(self, manual_log='', automated_log=''):
        self.devices = {}
        self.last_ts = 0
        self.manual_log = manual_log
        self.automated_log = automated_log

    def add_device(self, ip='', name='', mac='', type='', clf=None):
        self.devices[ip] = Device(
            ip=ip, name=name, mac=mac, type=type, 
            manual_log=self.manual_log, automated_log=self.automated_log,
            clf=clf
        )

    def new_pkt(self, pkt, pkt_id, filter_inout=None, IP_filter=[]):
        ret = 0

        if (Ether not in pkt or pkt[Ether].type == VLAN) or (IP not in pkt):
            return ret
        # ARP spoofing duplicate packets Source: Dell_43:6d:00 (50:9a:4c:43:6d:00)
        if pkt[Ether].src == 'dc:a6:32:7f:9c:0a' or pkt[Ether].src == '50:9a:4c:43:6d:00':
            return ret
        
        padding = 0
        if sc.Padding in pkt:
            padding = len(pkt[sc.Padding])
        elif (TCP in pkt 
              and len(pkt[TCP].payload) - padding == 0 
              and (not pkt[TCP].flags & MEANINGFUL_FLAG)):
            return ret
        elif sc.DNS in pkt:
            self._handle_dns(pkt)
        elif sc.NTP in pkt:
            self._handle_ntp(pkt)
        elif sc.DHCP in pkt:
            self._handle_dhcp(pkt)
        else:
            if pkt[IP].src in self.devices:
                ret = self.devices[pkt[IP].src].new_pkt(pkt, pkt_id)
                if ret != 0:
                    print('Drop packet', ret, self.devices[pkt[IP].src].name, pkt_id)

            elif pkt[IP].dst in self.devices:
                ret = self.devices[pkt[IP].dst].new_pkt(pkt, pkt_id)
                if ret != 0:
                    print('Drop packet', ret, self.devices[pkt[IP].dst].name, pkt_id)

        return ret

    def _handle_dns(self, pkt):
        if UDP not in pkt or pkt[UDP].sport != 53:
            return
        for x in range(pkt[sc.DNS].ancount):
            rdata = pkt[sc.DNS].an[x].rdata
            if type(rdata) is bytes:
                rdata = rdata.decode('utf-8')
                if MODE == 'DomainNoDigit':
                    rdata = rdata.translate(REMOVE_DIGITS)
            rrname = pkt[sc.DNS].an[x].rrname.decode('utf-8')
            if MODE == 'DomainNoDigit':
                rrname = rrname.translate(REMOVE_DIGITS)

            if pkt[sc.DNS].an[x].type == 5: # CNAME
                utils.LOCAL_DNS[rdata] = rrname
            elif  pkt[sc.DNS].an[x].type == 1: #
                if pkt[sc.DNS].an[x].rrname in utils.LOCAL_DNS:
                    utils.LOCAL_DNS[rdata] = rrname
                else:
                    utils.LOCAL_DNS[rdata] = rrname

    def _handle_ntp(self, pkt):
        pass

    def _handle_dhcp(self, pkt):
        pass

    def save_short_features(self, output_file):
        results = {
            de.name: de.get_short_features()
            for de in self.devices.values()
        }
        json.dump(results, open(output_file, 'w'))

    def save_long_features(self, output_file):
        results = {
            de.name: de.get_long_features()
            for de in self.devices.values()
        }
        json.dump(results, open(output_file, 'w'))


if __name__ == "__main__":
    start_ts, end_ts, filter_inout, filter_file = None, None, None, None
    if len(sys.argv) <= 3 or len(sys.argv) == 11 or len(sys.argv) >= 13:
        print('Input format: python proxy_predict.py mode device_file input_file [output_prefix] [manual_log] [automated_log] [warning_file] [start_ts end_ts] [(in/out) filter_file]')
        exit()
    elif len(sys.argv) == 4:
        output_prefix = ''
        manual_log = ''
        automated_log = ''
        warning_file = 'warnings'
    if len(sys.argv) >= 5:
        output_prefix = sys.argv[4]
        manual_log = ''
        automated_log = ''
        warning_file = 'warnings.json'
    if len(sys.argv) >= 6:
        manual_log = sys.argv[5]
    if len(sys.argv) >= 7:
        automated_log = sys.argv[6]
    if len(sys.argv) >= 8:
        warning_file = sys.argv[7]
    if len(sys.argv) >= 10:
        start_ts = float(sys.argv[8]) if sys.argv[8] != None else None
        end_ts = float(sys.argv[9]) if sys.argv[9] != None else None
    if len(sys.argv) >= 12:
        filter_inout = sys.argv[10]
        if filter_inout != 'in' and filter_inout != 'out':
            print('Input format: python regular_trace_extract.py mode device_file input_file [output_prefix] [output_prefix] [manual_log] [start_ts end_ts] [(in/out) filter_file]')
            exit()
        filter_file = sys.argv[11]

    MODE = sys.argv[1]
    if MODE not in ['Classic', 'PortLess', 'SubnetLess8', 'SubnetLess16', 'NSLookup', 'DomainNoDigit']:
        print("mode must be one of the following: ['Classic', 'PortLess', 'SubnetLess8', 'SubnetLess16', 'NSLookup', 'DomainNoDigit']")
    device_file = sys.argv[2]
    input_files = sys.argv[3]
    input_files = input_files.split(',')
    print(output_prefix)

    # devices = json.load(open(device_file, 'r'))
    devices = [
        {
            "name": "HomeMini", "mac": "30:fd:38:7b:62:51", "ip": "192.168.5.14", 
            "clf": "../models/HomeMini.joblib"
        },
        {
            "name": "Wyze", "mac": "2c:aa:8e:15:da:5b", "ip": "192.168.5.15", 
            "clf": "../models/WyzeCam.joblib"
        }
    ]
    # try:
    #     utils.LOCAL_DNS = json.load(open('local_dns_%s.json' % (MODE), 'r'))
    # except:
    #     print('No local dns file found')
    predictor = Predictor(manual_log=manual_log, automated_log=automated_log)
    for de in devices:
        if 'type' in de:
            continue
        predictor.add_device(**de)
    IP_filters = []
    if filter_inout == 'in':
        IP_filters = json.load(open(filter_file, 'r'))


    total_count = 0
    for infile in input_files:
        targets = []
        if os.path.isdir(infile):
            targets = [os.path.join(infile, x) for x in sorted(os.listdir(infile))]
        else:
            targets = [infile]
        for target in targets:
            print('Processing %s' % target)
            target_count = 0
            try:
                pcap_reader = PcapReader(target)
            except Exception as e:
                print('Exception!', target, e)
                continue 

            for pkt in pcap_reader:
                total_count += 1
                target_count += 1
                if total_count % 20000 == 0:
                    print('%f, Packet No. %d' % (time.time(), total_count))

                if start_ts and pkt.time < start_ts:
                    continue
                if end_ts and pkt.time > end_ts:
                    continue
                
                ret = predictor.new_pkt(pkt, (target, target_count), filter_inout, IP_filters)

    # predictor.save_short_features(os.path.join(output_prefix, 'short_features.json'))
    # predictor.save_long_features(os.path.join(output_prefix, 'long_features.json'))

    # if filter_inout == 'out':
    #     json.dump(IP_filters, open(filter_file, 'w'))
    # json.dump(utils.LOCAL_DNS, open(os.path.join(output_prefix, 'dns.json'), 'w'))


# python3 predictor.py DomainNoDigit ../../trace/BatteryLab2/vpn/devices.json ../../trace/BatteryLab2/vpn/94.198.40.99/pcaps ../../trace/BatteryLab2/vpn/test > test.log
