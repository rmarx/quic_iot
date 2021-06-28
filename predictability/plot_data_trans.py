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


def plot_device(device, device_name, output_dir, symlog=False, x_min=None, x_max=None):
    print('plot_device', device_name, output_dir)
    plt.clf()
    fig, ax = plt.subplots(figsize=(24, 12))

    flow_count = 0
    label_count = 0
    for flow_id, flow in device.items():
        X = [int(ts) for ts in flow]
        X = [x for x in range(min(X)-1, max(X)+2)]
        if x_min and x_max:
            X = [x for x in range(int(x_min)-1, int(x_max)+1)]
        X_date = [datetime.fromtimestamp(x) for x in X]
        Ys = [flow[str(x)][0] if str(x) in flow else 0 for x in X]
        if len(X) > 30:
            if label_count < 50:
                plt.plot(X_date, Ys, color=colors[flow_count % len(colors)], linewidth=2, label=flow_id, linestyle='dashed')
                label_count += 1
            else:
                plt.plot(X_date, Ys, color=colors[flow_count % len(colors)], linewidth=2, linestyle='dashed')
        else:
            if label_count < 50:
                plt.plot(X_date, Ys, color=colors[flow_count % len(colors)], linewidth=2, label=flow_id)
                label_count += 1
            else:
                plt.plot(X_date, Ys, color=colors[flow_count % len(colors)], linewidth=2)
        Ys = [-flow[str(x)][1] if str(x) in flow else 0 for x in X]
        if len(X) > 30:
            plt.plot(X_date, Ys, color=colors[flow_count % len(colors)], linewidth=2, linestyle='dashed')
        else:
            plt.plot(X_date, Ys, color=colors[flow_count % len(colors)], linewidth=2)
        flow_count += 1

    plt.ylabel('Send (-) / Recv (+) Bytes')
    if symlog:
        plt.yscale('symlog')
    # myFmt = mdates.DateFormatter('%m/%d')
    # ax.xaxis.set_major_formatter(myFmt)
    plt.tight_layout()
    plt.grid(True)
    plt.legend(loc='upper right', prop={'size': 10})

    if symlog:
        plt.savefig(os.path.join(output_dir, device_name) + '_log.pdf')
    else:
        plt.savefig(os.path.join(output_dir, device_name) + '.pdf')

if __name__ == "__main__":
    start_ts, end_ts = None, None
    if len(sys.argv) == 2:
        input_file = sys.argv[1]
        output_dir = './'
    elif len(sys.argv) == 3:
        input_file = sys.argv[1]
        output_dir = sys.argv[2]
    elif len(sys.argv) == 5:
        input_file = sys.argv[1]
        output_dir = sys.argv[2]
        start_ts = sys.argv[3]
        end_ts = sys.argv[4]
    else: #if len(sys.argv) < 2:
        print('Input format: python plot_data_trans.py input_file [output_dir] [start_ts end_ts]')
        exit()

    devices = json.load(open(input_file, 'r'))
    for device_name, device in devices.items():
        if len(device) > 0:
            plot_device(device, device_name, output_dir, x_min=start_ts, x_max=end_ts)
            plot_device(device, device_name, output_dir, symlog=True, x_min=start_ts, x_max=end_ts)

# python3 plot_data_trans.py yourthing/processed/output.json yourthing/processed