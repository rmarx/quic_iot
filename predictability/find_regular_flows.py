import time
import json 
import sys
import hashlib
import operator
import numpy as np
import os

from datetime import datetime
import re
import json

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as tick
import matplotlib.dates as mdates
from matplotlib import rcParams
rcParams.update({'figure.autolayout': True})
rcParams.update({'figure.autolayout': True})
rcParams.update({'errorbar.capsize': 2})

# increase font 
font = {'weight' : 'medium',
        'size'   : 16}
matplotlib.rc('font', **font)

colors = [
    'tab:blue', 'tab:orange', 'tab:green', 'tab:red', 'tab:purple',
    'tab:brown', 'tab:pink', 'tab:gray', 'tab:olive', 'tab:cyan', 'black'
]


def count_regular_traffic(device, device_name):
    print('count_regular_traffic', device_name)
    regular_flows1, nonrg_flows1 = [], []
    regular_flows2, nonrg_flows2 = [], []
    regular_flows3, nonrg_flows3 = [], []

    regular_flows_vol1, nonrg_flows_vol1, max_interval1 = [], [], []
    regular_flows_vol2, nonrg_flows_vol2, max_interval2 = [], [], []
    regular_flows_vol3, nonrg_flows_vol3 = [], []

    for flow_id, flow in device.items():
        X = [int(ts) for ts in flow]
        Ys = [flow[str(x)][0]+flow[str(x)][1] for x in X]

        diffs1, diffs2 = [], []
        match1, match2 = 0, 0
        ignore1, ignore2 = 0, 0
        max_int1, max_int2 = 0, 0
        for i in range(1, len(X)):
            diff = X[i] - X[i-1]
            if diff in diffs1:
                match1 += 1
                max_int1 = max(max_int1, diff)
            else:
                diffs1.append(diff)
                ignore1 += 1
            if diff in diffs2:
                match2 += 1
                max_int2 = max(max_int2, diff)
            else:
                diffs2.append(diff-1)
                diffs2.append(diff)
                diffs2.append(diff+1)
                ignore2 += 1

        # if device_name == 'MiCasaVerdeVeraLite-192.168.0.34':
        #     print('flow_id', flow_id)
        #     print('X', X)
        #     print('Ys', Ys)
        #     print('diffs1', diffs1)
        #     print('len1', match1, len(X), ignore1)
        #     print('diffs2', diffs2)
        #     print('len2', match2, len(X), ignore2)
        
        if len(X) - ignore1 - 1 > 0 and match1 / float(len(X) - ignore1 - 1) >= 0.8:
            regular_flows1.append(flow_id)
            regular_flows_vol1.append(sum(Ys))
        else:
            nonrg_flows1.append(flow_id)
            nonrg_flows_vol1.append(sum(Ys))
        max_interval1.append(max_int1)
        
        if len(X) - ignore2 - 1 > 0 and match2 / float(len(X) - ignore2 - 1) >= 0.8:
            regular_flows2.append(flow_id)
            regular_flows_vol2.append(sum(Ys))
        else:
            nonrg_flows2.append(flow_id)
            nonrg_flows_vol2.append(sum(Ys))
        max_interval2.append(max_int2)
        
        if max(X) - min(X) > 30:
            regular_flows3.append(flow_id)
            regular_flows_vol3.append(sum(Ys))
        else:
            nonrg_flows3.append(flow_id)
            nonrg_flows_vol3.append(sum(Ys))
    
    detail = {'regular_flows1': regular_flows1, 'nonrg_flows1': nonrg_flows1, 
               'regular_flows2': regular_flows2, 'nonrg_flows2': nonrg_flows2, 
               'regular_flows3': regular_flows3, 'nonrg_flows3': nonrg_flows3}

    summary = {
        'regular_flows1': {'count': len(regular_flows1), 'vol': sum(regular_flows_vol1), 'max_int': max(max_interval1)}, 
        'nonrg_flows1': {'count': len(nonrg_flows1), 'vol': sum(nonrg_flows_vol1)}, 
        'regular_flows2': {'count': len(regular_flows2), 'vol': sum(regular_flows_vol2), 'max_int': max(max_interval2)}, 
        'nonrg_flows2': {'count': len(nonrg_flows2), 'vol': sum(nonrg_flows_vol2)}, 
        'regular_flows3': {'count': len(regular_flows3), 'vol': sum(regular_flows_vol3)}, 
        'nonrg_flows3': {'count': len(nonrg_flows3), 'vol': sum(nonrg_flows_vol3)}
    }

    return detail, summary


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print('Input format: python find_regular_flow.py device_file input_file [output_dir]')
        exit()
    elif len(sys.argv) == 3:
        device_file = sys.argv[1]
        input_file = sys.argv[2]
        outputfile_detail = 'regular_details.json'
        outputfile_summary = 'regular_summary.json'
    else:
        device_file = sys.argv[1]
        input_file = sys.argv[2]
        outputfile_detail = os.path.join(sys.argv[3], 'regular_details.json')
        outputfile_summary = os.path.join(sys.argv[3], 'regular_summary.json')

    devices_setting = json.load(open(device_file, 'r'))
    non_iot_devices = []
    for d in devices_setting:
        if 'type' in d:
            non_iot_devices.append(d['name'])
    print('non_iot_devices', non_iot_devices)

    details = {}
    summaries = {}
    devices = json.load(open(input_file, 'r'))
    for device_name, device in devices.items():
        ignore_flag = False
        for non_iot_d in non_iot_devices:
            if non_iot_d in device_name:
                print('IGNORE ' + device_name +' because it is not an IoT device')
                ignore_flag = True
                continue
        if len(device) > 0 and ignore_flag is False:
            detail, summary = count_regular_traffic(device, device_name)
            details[device_name] = detail
            summaries[device_name] = summary
    
    try:
        all_details = json.load(open(outputfile_detail, 'r'))
    except Exception as e:
        print('Rad outputfile_detail failed:', e, outputfile_detail)
        all_details = {}
    all_details.update({input_file: details})
    json.dump(all_details, open(outputfile_detail, 'w'))

    try:
        all_summaries = json.load(open(outputfile_summary, 'r'))
    except Exception as e:
        print('ad outputfile_summary failed:', e, outputfile_summary)
        all_summaries = {}
    all_summaries.update({input_file: summaries})
    json.dump(all_summaries, open(outputfile_summary, 'w'))
    

# python3 find_regular_flows.py yourthing/devices.json results/yourthing/11/results/output.json results/yourthing
# python3 find_regular_flows.py yourthing/devices.json results/yourthing/11/results_noport/output.json results/yourthing
# python3 find_regular_flows.py yourthing/devices.json results/yourthing/12/results/output.json results/yourthing
# python3 find_regular_flows.py yourthing/devices.json results/yourthing/12/results_noport/output.json results/yourthing