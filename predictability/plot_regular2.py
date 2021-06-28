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


def plot_regular_proportion(summary, output_dir):
    print('plot_regular_proportion', output_dir)
    # fig, ax = plt.subplots(figsize=(24, 12))

    MODES = ['Classic', 'PortLess', 'SubnetLess8', 'SubnetLess16', 'NSLookup', 'DomainNoDigit']
    percentages = {
        MODE: {
            'reguarl1': {'count': [], 'volume': [], 'max_int': []},
            'reguarl2': {'count': [], 'volume': [], 'max_int': []},
            'reguarl3': {'count': [], 'volume': []},
        }
        for MODE in MODES
    }

    for trace_id, trace in summary.items():
        for device_id, device in trace.items():
            # if 'noport' in trace_id:
            for MODE in MODES:
                if MODE in trace_id:
                    percentages[MODE]['reguarl1']['count'].append(
                        100 * device['regular_flows1']['count'] / float(device['regular_flows1']['count'] + device['nonrg_flows1']['count'])
                    )
                    percentages[MODE]['reguarl1']['volume'].append(
                        100 * device['regular_flows1']['vol'] / float(device['regular_flows1']['vol'] + device['nonrg_flows1']['vol'])
                    )
                    percentages[MODE]['reguarl1']['max_int'].append(
                        device['regular_flows1']['max_int']
                    )

                    percentages[MODE]['reguarl2']['count'].append(
                        100 * device['regular_flows2']['count'] / float(device['regular_flows2']['count'] + device['nonrg_flows2']['count'])
                    )
                    percentages[MODE]['reguarl2']['volume'].append(
                        100 * device['regular_flows2']['vol'] / float(device['regular_flows2']['vol'] + device['nonrg_flows2']['vol'])
                    )
                    percentages[MODE]['reguarl2']['max_int'].append(
                        device['regular_flows2']['max_int']
                    )

                    percentages[MODE]['reguarl3']['count'].append(
                        100 * device['regular_flows3']['count'] / float(device['regular_flows3']['count'] + device['nonrg_flows3']['count'])
                    )
                    percentages[MODE]['reguarl3']['volume'].append(
                        100 * device['regular_flows3']['vol'] / float(device['regular_flows3']['vol'] + device['nonrg_flows3']['vol'])
                    )

    plt.clf()
    for i in range(len(MODES)):
        results = percentages[MODES[i]]['reguarl1']['count']
        x, y = sorted(results), np.arange(1, 1 + len(results)) / len(results)
        plt.plot(x, y, label=MODES[i], color=colors[i], linewidth = 2)
    plt.ylim(0, 1)
    plt.ylabel('CDF (0-1)')
    plt.xlabel('Predictable (%)')
    plt.tight_layout()
    plt.grid(True)
    plt.legend()#prop={'size': 10})
    plt.savefig(os.path.join(output_dir, 'cdf_predict1_count.pdf'))

    plt.clf()
    for i in range(len(MODES)):
        results = percentages[MODES[i]]['reguarl2']['count']
        x, y = sorted(results), np.arange(1, 1 + len(results)) / len(results)
        plt.plot(x, y, label=MODES[i], color=colors[i], linewidth = 2)
    plt.ylim(0, 1)
    plt.ylabel('CDF (0-1)')
    plt.xlabel('Predictable (%)')
    plt.tight_layout()
    plt.grid(True)
    plt.legend()#prop={'size': 10})
    plt.savefig(os.path.join(output_dir, 'cdf_predict2_count.pdf'))

    plt.clf()
    for i in range(len(MODES)):
        results = percentages[MODES[i]]['reguarl1']['volume']
        x, y = sorted(results), np.arange(1, 1 + len(results)) / len(results)
        plt.plot(x, y, label=MODES[i], color=colors[i], linewidth = 2)
    plt.ylim(0, 1)
    plt.ylabel('CDF (0-1)')
    plt.xlabel('Predictable (%)')
    plt.tight_layout()
    plt.grid(True)
    plt.legend()#prop={'size': 10})
    plt.savefig(os.path.join(output_dir, 'cdf_predict1_volume.pdf'))

    plt.clf()
    for i in range(len(MODES)):
        results = percentages[MODES[i]]['reguarl2']['volume']
        x, y = sorted(results), np.arange(1, 1 + len(results)) / len(results)
        plt.plot(x, y, label=MODES[i], color=colors[i], linewidth = 2)
    plt.ylim(0, 1)
    plt.ylabel('CDF (0-1)')
    plt.xlabel('Predictable (%)')
    plt.tight_layout()
    plt.grid(True)
    plt.legend()#prop={'size': 10})
    plt.savefig(os.path.join(output_dir, 'cdf_predict2_volume.pdf'))


    plt.clf()
    for i in range(len(MODES)):
        results = percentages[MODES[i]]['reguarl1']['max_int']
        x, y = sorted(results), np.arange(1, 1 + len(results)) / len(results)
        plt.plot(x, y, label=MODES[i], color=colors[i], linewidth = 2)
    plt.ylim(0, 1)
    plt.ylabel('CDF (0-1)')
    plt.xlabel('Maximal Interval For Predictable Traffic (s)')
    plt.tight_layout()
    plt.grid(True)
    plt.legend()#prop={'size': 10})
    plt.savefig(os.path.join(output_dir, 'cdf_predict1_maxint.pdf'))

    plt.clf()
    for i in range(len(MODES)):
        results = percentages[MODES[i]]['reguarl2']['max_int']
        x, y = sorted(results), np.arange(1, 1 + len(results)) / len(results)
        plt.plot(x, y, label=MODES[i], color=colors[i], linewidth = 2)
    plt.ylim(0, 1)
    plt.ylabel('CDF (0-1)')
    plt.xlabel('Maximal Interval For Predictable Traffic (s)')
    plt.tight_layout()
    plt.grid(True)
    plt.legend()#prop={'size': 10})
    plt.savefig(os.path.join(output_dir, 'cdf_predict2_maxint.pdf'))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Input format: python plot_data_trans.py input_dir [output_dir]')
        exit()
    elif len(sys.argv) == 2:
        input_dir = sys.argv[1]
        output_dir = './'
    else:
        input_dir = sys.argv[1]
        output_dir = sys.argv[2]

    # details_file = os.path.join(input_dir, 'regular_details.json')
    summary_file = os.path.join(input_dir, 'regular_summary.json')

    # details = json.load(open(details_file, 'r'))
    summary = json.load(open(summary_file, 'r'))

    plot_regular_proportion(summary, output_dir)

# python3 plot_regular.py results/yourthing results/yourthing