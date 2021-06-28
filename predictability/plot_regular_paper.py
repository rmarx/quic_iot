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
    'tab:blue', 'tab:red', 'tab:green', 'tab:orange', 'tab:purple',
    'tab:brown', 'tab:pink', 'tab:gray', 'tab:olive', 'tab:cyan', 'black'
]


def plot_regular_proportion(summary, output_dir):
    print('plot_regular_proportion', output_dir)
    # fig, ax = plt.subplots(figsize=(24, 12))

    percentages = {
        'noport': {
            'reguarl1': {'count': [], 'volume': [], 'max_int': []},
            'reguarl2': {'count': [], 'volume': [], 'max_int': []},
            'reguarl3': {'count': [], 'volume': []},
        },
        'withport': {
            'reguarl1': {'count': [], 'volume': [], 'max_int': []},
            'reguarl2': {'count': [], 'volume': [], 'max_int': []},
            'reguarl3': {'count': [], 'volume': []},
        }
    }
    for trace_id, trace in summary.items():
        for device_id, device in trace.items():
            if 'noport' in trace_id:
                try:
                    percentages['noport']['reguarl1']['count'].append(
                        100 * device['regular_flows1']['count'] / float(device['regular_flows1']['count'] + device['nonrg_flows1']['count'])
                    )
                    percentages['noport']['reguarl1']['volume'].append(
                        100 * device['regular_flows1']['vol'] / float(device['regular_flows1']['vol'] + device['nonrg_flows1']['vol'])
                    )
                except ZeroDivisionError:
                    percentages['noport']['reguarl1']['count'].append(100)
                    percentages['noport']['reguarl1']['volume'].append(100)
                percentages['noport']['reguarl1']['max_int'].append(
                    device['regular_flows1']['max_int']
                )

                try:
                    percentages['noport']['reguarl2']['count'].append(
                        100 * device['regular_flows2']['count'] / float(device['regular_flows2']['count'] + device['nonrg_flows2']['count'])
                    )
                    percentages['noport']['reguarl2']['volume'].append(
                        100 * device['regular_flows2']['vol'] / float(device['regular_flows2']['vol'] + device['nonrg_flows2']['vol'])
                    )
                except ZeroDivisionError:
                    percentages['noport']['reguarl2']['count'].append(100)
                    percentages['noport']['reguarl2']['volume'].append(100)
                percentages['noport']['reguarl2']['max_int'].append(
                    device['regular_flows2']['max_int']
                )

                try:
                    percentages['noport']['reguarl3']['count'].append(
                        100 * device['regular_flows3']['count'] / float(device['regular_flows3']['count'] + device['nonrg_flows3']['count'])
                    )
                    percentages['noport']['reguarl3']['volume'].append(
                        100 * device['regular_flows3']['vol'] / float(device['regular_flows3']['vol'] + device['nonrg_flows3']['vol'])
                    )
                except ZeroDivisionError:
                    percentages['noport']['reguarl3']['count'].append(100)
                    percentages['noport']['reguarl3']['volume'].append(100)
            else:
                try:
                    percentages['withport']['reguarl1']['count'].append(
                        100 * device['regular_flows1']['count'] / float(device['regular_flows1']['count'] + device['nonrg_flows1']['count'])
                    )
                    percentages['withport']['reguarl1']['volume'].append(
                        100 * device['regular_flows1']['vol'] / float(device['regular_flows1']['vol'] + device['nonrg_flows1']['vol'])
                    )
                except ZeroDivisionError:
                    percentages['withport']['reguarl2']['count'].append(100)
                    percentages['withport']['reguarl2']['volume'].append(100)
                percentages['withport']['reguarl1']['max_int'].append(
                    device['regular_flows1']['max_int']
                )

                try:
                    percentages['withport']['reguarl2']['count'].append(
                        100 * device['regular_flows2']['count'] / float(device['regular_flows2']['count'] + device['nonrg_flows2']['count'])
                    )
                    percentages['withport']['reguarl2']['volume'].append(
                        100 * device['regular_flows2']['vol'] / float(device['regular_flows2']['vol'] + device['nonrg_flows2']['vol'])
                    )
                except ZeroDivisionError:
                    percentages['withport']['reguarl2']['count'].append(100)
                    percentages['withport']['reguarl2']['volume'].append(100)
                percentages['withport']['reguarl2']['max_int'].append(
                    device['regular_flows2']['max_int']
                )

                try:
                    percentages['withport']['reguarl3']['count'].append(
                        100 * device['regular_flows3']['count'] / float(device['regular_flows3']['count'] + device['nonrg_flows3']['count'])
                    )
                    percentages['withport']['reguarl3']['volume'].append(
                        100 * device['regular_flows3']['vol'] / float(device['regular_flows3']['vol'] + device['nonrg_flows3']['vol'])
                    )
                except ZeroDivisionError:
                    percentages['withport']['reguarl3']['count'].append(100)
                    percentages['withport']['reguarl3']['volume'].append(100)

    plt.clf()
    results = percentages['withport']['reguarl2']['volume']
    x, y = sorted(results), np.arange(1, 1 + len(results)) / len(results)
    plt.plot(x, y, label='Traffic Volume-Classic', color=colors[0], linewidth = 2)

    results = percentages['noport']['reguarl2']['volume']
    x, y = sorted(results), np.arange(1, 1 + len(results)) / len(results)
    plt.plot(x, y, label='Traffic Volume-PortLess', color=colors[1], linewidth = 2)

    results = percentages['withport']['reguarl2']['count']
    x, y = sorted(results), np.arange(1, 1 + len(results)) / len(results)
    plt.plot(x, y, label='Num of Flow-Classic', color=colors[2], linewidth = 2)

    results = percentages['noport']['reguarl2']['count']
    x, y = sorted(results), np.arange(1, 1 + len(results)) / len(results)
    plt.plot(x, y, label='Num of Flow-PortLess', color=colors[3], linewidth = 2)


    plt.ylim(0, 1)
    plt.xlim(0, 100)
    plt.ylabel('CDF (0-1)')
    plt.xlabel('Predictable (%)')
    plt.tight_layout()
    plt.grid(True)
    plt.legend()#prop={'size': 10})
    # plt.savefig(os.path.join(output_dir, 'cdf_predictable_yourthing.pdf'))
    # plt.savefig(os.path.join(output_dir, 'cdf_predictable_moniotr_active.pdf'))
    plt.savefig(os.path.join(output_dir, 'cdf_predictable_moniotr_idle.pdf'))


    plt.clf()
    results = percentages['withport']['reguarl1']['max_int']
    x, y = sorted(results), np.arange(1, 1 + len(results)) / len(results)
    plt.plot(x, y, label='Classic', color=colors[0], linewidth = 2)

    results = percentages['noport']['reguarl1']['max_int']
    x, y = sorted(results), np.arange(1, 1 + len(results)) / len(results)
    plt.plot(x, y, label='PortLess', color=colors[1], linewidth = 2)

    plt.ylim(0, 1)
    plt.ylabel('CDF (0-1)')
    plt.xlabel('Maximum Interval For Predictable Traffic (s)')
    plt.tight_layout()
    plt.grid(True)
    plt.legend()#prop={'size': 10})
    plt.savefig(os.path.join(output_dir, 'cdf_maxint.pdf'))


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
    # summary_file = os.path.join(input_dir, 'regular_summary_1h.json')

    # details = json.load(open(details_file, 'r'))
    summary = json.load(open(summary_file, 'r'))

    plot_regular_proportion(summary, output_dir)

# python3 plot_regular.py results/yourthing results/yourthing