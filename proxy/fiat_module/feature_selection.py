import json
import time

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

from string import digits
from datetime import datetime

import numpy as np

import fiat_module.utils

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

def get_tls_version(pkt):
    ret = 0
    if TCP in pkt:
        try:
            if TLS in pkt:
                ret = pkt[TLS].version
            elif TLS in TLS(bytes(pkt[TCP].payload)):
                ret = TLS(bytes(pkt[TCP].payload)).version
        except Exception as e:
            print('proto error!', e, pkt)
    elif UDP in pkt:
        try:
            if TLS in pkt:
                ret = pkt[TLS].version
            elif TLS in TLS(bytes(pkt[UDP].payload)):
                ret = TLS(bytes(pkt[UDP].payload)).version
        except Exception as e:
            print('proto error!', e, pkt)
    return ret

NUM_SHORT_FEATURE = 12 
def extract_feature_short(pkts, device_ip):
    # features:
    # dst_IP, dst_domain, 
    # tcp/udp, flags, src_port, dst_port, 
    # tls,
    # pkt size, inter-arrival time 
    features = []

    pkt_sizes = []
    int_times = []
    last_ts = 0
    for pkt in pkts:
        pkt_sizes.append(len(pkt))
        if pkt[IP].src == device_ip:
            features.append(1)
            features.extend([int(dst) for dst in pkt[IP].dst.split('.')])
            # features.append(utils.LOCAL_DNS[pkt[IP].dst])
            if TCP in pkt:
                features.append(0)
                features.append(int(pkt[TCP].flags) & MEANINGFUL_FLAG)
                features.append(pkt[TCP].sport)
                features.append(pkt[TCP].dport)
                features.append(get_tls_version(pkt))
                # if TLS in pkt:
                #     features.append(pkt[TLS].version)
                # elif TLS in TLS(pkt[TCP].payload):
                #     features.append(TLS(pkt[TCP].payload).version)
                # else:
                #     features.append(0)
                features.append(len(pkt))
            elif UDP in pkt:
                features.append(1)
                features.append(0)
                features.append(pkt[UDP].sport)
                features.append(pkt[UDP].dport)
                features.append(get_tls_version(pkt))
                # if TLS in pkt:
                #     features.append(pkt[TLS].version)
                # elif TLS in TLS(pkt[UDP].payload):
                #     features.append(TLS(pkt[UDP].payload).version)
                # else:
                #     features.append(0)
                features.append(len(pkt))
            else:
                features.append([-1] * 6)
        else:
            features.append(0)
            features.extend([int(src) for src in pkt[IP].src.split('.')])
            # features.append(utils.LOCAL_DNS[pkt[IP].src])
            if TCP in pkt:
                features.append(0)
                features.append(int(pkt[TCP].flags) & MEANINGFUL_FLAG)
                features.append(pkt[TCP].dport)
                features.append(pkt[TCP].sport)
                features.append(get_tls_version(pkt))
                # if TLS in pkt:
                #     features.append(pkt[TLS].version)
                # elif TLS in TLS(bytes(pkt[TCP].payload)):
                #     features.append(TLS(bytes(pkt[TCP].payload)).version)
                # else:
                #     features.append(0)
                features.append(len(pkt))
            elif UDP in pkt:
                features.append(1)
                features.append(0)
                features.append(pkt[UDP].dport)
                features.append(pkt[UDP].sport)
                features.append(get_tls_version(pkt))
                # if TLS in pkt:
                #     features.append(pkt[TLS].version)
                # elif TLS in TLS(bytes(pkt[UDP].payload)):
                #     features.append(TLS(bytes(pkt[UDP].payload)).version)
                # else:
                #     features.append(0)
                features.append(len(pkt))
            else:
                features.append([-1] * 6)

        if last_ts == 0:
            features.append(0)
        else:
            features.append(float(pkt.time) - last_ts)
            int_times.append(float(pkt.time) - last_ts)
        last_ts = float(pkt.time)

    if len(pkts) < utils.SHORT_PKT_THRES:
        features.extend([-1] * NUM_SHORT_FEATURE * int(utils.SHORT_PKT_THRES - len(pkts)))
        # features.extend(
        #     [-1] * int(
        #         (utils.SHORT_PKT_THRES - len(pkts)) * (len(features) / len(pkts))
        #     ))

    features.append(len(pkt_sizes))
    features.append(np.average(pkt_sizes))
    features.append(np.std(pkt_sizes))

    features.append(sum(int_times))
    features.append(np.average(int_times))
    features.append(np.std(int_times))

    return features


NUM_LONG_FEATURE = 11 # 12
def extract_feature_long(pkts, device_ip):
    # features:
    # first 3 distinct dst ip, 
    # tcp/udp, flags, src_port, dst_port, 
    # tls,
    # pkt size, inter-arrival time 
    features = []
    distinct_ip = []
    last_ts = 0
    inter_arrival_time = []
    pkt_sizes = []
    upload, download = [], []
    for pkt in pkts:
        if last_ts == 0:
            last_ts = float(pkt.time)
        else:
            inter_arrival_time.append(float(pkt.time) - last_ts)
            last_ts = float(pkt.time)
        pkt_sizes.append(len(pkt))

        # first 3 distinct ip
        if pkt[IP].src == device_ip:
            upload.append(len(pkt))
            if (pkt[IP].dst not in distinct_ip) and len(distinct_ip) < 3:
                distinct_ip.append(pkt[IP].dst)
                features.extend(pkt[IP].dst.split('.'))
                if TCP in pkt:
                    features.append(0)
                    features.append(int(pkt[TCP].flags))
                    features.append(pkt[TCP].sport)
                    features.append(pkt[TCP].dport)
                    features.append(get_tls_version(pkt))
                    # features.append(pkt[TLS].version if TLS in pkt else 0)
                    features.append(len(pkt))
                elif UDP in pkt:
                    features.append(1)
                    features.append(0)
                    features.append(pkt[UDP].sport)
                    features.append(pkt[UDP].dport)
                    features.append(get_tls_version(pkt))
                    # features.append(0)
                    features.append(len(pkt))
                else:
                    features.append([-1] * 6)
        else:
            download.append(len(pkt))
            if (pkt[IP].src not in distinct_ip) and len(distinct_ip) < 3:
                distinct_ip.append(pkt[IP].src)
                features.extend(pkt[IP].src.split('.'))
                if TCP in pkt:
                    features.append(0)
                    features.append(int(pkt[TCP].flags))
                    features.append(pkt[TCP].sport)
                    features.append(pkt[TCP].dport)
                    features.append(get_tls_version(pkt))
                    # features.append(pkt[TLS].version if TLS in pkt else 0)
                    features.append(len(pkt))
                elif UDP in pkt:
                    features.append(1)
                    features.append(0)
                    features.append(pkt[UDP].sport)
                    features.append(pkt[UDP].dport)
                    features.append(get_tls_version(pkt))
                    # features.append(0)
                    features.append(len(pkt))
                else:
                    features.append([-1] * 6)

    if len(features) < 3*NUM_LONG_FEATURE:
        features.extend([-1] * (3*NUM_LONG_FEATURE - len(features)))
    
    # statistics
    features.append(len(pkts))
    features.append(np.average(pkt_sizes))
    features.append(np.std(pkt_sizes))
    features.append(min(pkt_sizes))
    features.append(np.percentile(pkt_sizes, 25))
    features.append(np.percentile(pkt_sizes, 50))
    features.append(np.percentile(pkt_sizes, 75))
    features.append(max(pkt_sizes))

    features.append(sum(inter_arrival_time))
    features.append(np.average(inter_arrival_time))
    features.append(np.std(inter_arrival_time))
    features.append(min(inter_arrival_time))
    features.append(np.percentile(inter_arrival_time, 25))
    features.append(np.percentile(inter_arrival_time, 50))
    features.append(np.percentile(inter_arrival_time, 75))
    features.append(max(inter_arrival_time))

    features.append(float(sum(download)) / (sum(upload)+sum(download)))

    return features