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


def plot_warning(devices, non_iot_devices, output_dir, method, interval=1, symlog=False, x_min=None, x_max=None):
    plt.clf()
    fig, ax = plt.subplots(figsize=(24, 12))

    device_count = -1
    for device_name, warnings in sorted(devices.items()):
        ignore_flag = False
        for non_iot_d in non_iot_devices:
            if non_iot_d in device_name:
                print('IGNORE ' + device_name +' because it is not an IoT device')
                ignore_flag = True
                continue
        
        if ignore_flag or len(warnings) == 0:# or 'EchoDot' in device_name.split('-')[0]:
            continue
        device_count += 1
        
        # print(device_name, warnings)
        X = [int(ts) for ts in warnings]
        X = [x for x in range(min(X)-1, max(X)+2)]
        if x_min and x_max:
            X = [x for x in range(int(x_min)-1, int(x_max)+1)]
        Ys = [warnings[str(x)] if str(x) in warnings else 0 for x in X]
        merge = {}
        for i in range(len(X)):
            merge[X[i] - (X[i] % interval)] = merge.get(X[i] - (X[i] % interval), 0) + Ys[i]
        
        X = [x for x in sorted(merge)]
        X_date = [datetime.fromtimestamp(x) for x in sorted(merge)]
        Ys = [merge[x] for x in sorted(merge)]

        plt.plot(X_date, Ys, color=colors[device_count % len(colors)], linewidth=2, label=device_name.split('-')[0])

    plt.ylabel('Number of Warnings Per Second')
    if symlog:
        plt.yscale('symlog')
    # myFmt = mdates.DateFormatter('%m/%d')
    # ax.xaxis.set_major_formatter(myFmt)
    plt.tight_layout()
    plt.grid(True)
    plt.legend(loc='upper right', prop={'size': 10})

    if symlog:
        plt.savefig(os.path.join(output_dir, 'warnings%d_%s_log.pdf' % (interval, method)))
    else:
        plt.savefig(os.path.join(output_dir, 'warnings%d_%s.pdf' % (interval, method)))


if __name__ == "__main__":
    method, start_ts, end_ts = '', None, None
    if len(sys.argv) == 5:
        method = sys.argv[1]
        interval = int(sys.argv[2])
        device_file = sys.argv[3]
        input_file = sys.argv[4]
        output_dir = './'
    elif len(sys.argv) == 6:
        method = sys.argv[1]
        interval = int(sys.argv[2])
        device_file = sys.argv[3]
        input_file = sys.argv[4]
        output_dir = sys.argv[5]
    elif len(sys.argv) == 8:
        method = sys.argv[1]
        interval = int(sys.argv[2])
        device_file = sys.argv[3]
        input_file = sys.argv[4]
        output_dir = sys.argv[5]
        start_ts = sys.argv[6]
        end_ts = sys.argv[7]
    else: #if len(sys.argv) < 2:
        print('Input format: python plot_data_trans.py method interval device_file input_file [output_dir] [start_ts end_ts]')
        exit()

    devices_setting = json.load(open(device_file, 'r'))
    non_iot_devices = []
    for d in devices_setting:
        if 'type' in d:
            non_iot_devices.append(d['name'])
    print('non_iot_devices', non_iot_devices)

    devices = json.load(open(input_file, 'r'))
    plot_warning(devices, non_iot_devices, output_dir, method, interval=interval, symlog=False, x_min=start_ts, x_max=end_ts)
    # plot_warning(devices, non_iot_devices, output_dir, method, interval=interval, symlog=True, x_min=start_ts, x_max=end_ts)

# python3 plot_data_trans.py yourthing/processed/output.json yourthing/processed