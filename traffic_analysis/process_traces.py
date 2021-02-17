# some code inspired by https://github.com/NEU-SNS/intl-iot/tree/master/destination

# our trace processing pipeline works in three steps, of which this file is the entrypoint for step 1
# step 1. process individual pcaps and store connection-level information in a separate .json file per device
# step 2. process the per-device .json files to perform more high-level analysis (see analyse_connections)
# step 3. summarize the per-device results into global statistics (e.g., across n devices, x did this, y did this)

# These separate steps are needed due to the heterogeneity of dataset formats we deal with
# Some datasets split the device behaviour across multiple pcaps, while others just contain all traffic for all devices in one pcap for a given time interval
# Performing the high-level analysis across traces would thus become difficult in a single pass, which is why the two-stage approach was chosen

import argparse
import os
import shutil
import re
import sys
from multiprocessing import Process
import gc
import time
from random import random
import json
import multiprocessing

from util.Util import Util
from lib.models.Connection import Connection
import lib.models.Device as Device
from lib.processors.TraceProcessor import TraceProcessor


device_list = None
verbose = False

def main():
    global device_list, verbose

    start_time = time.time()

    # example:
    # - manually set the in/out directories, experiment_list, device_list below
    # - call: python3 process_traces.py --override True -p 1

    print("Processing pcaps")
    print("Start time: %s\n" % time.strftime("%A %d %B %Y %H:%M:%S %Z", time.localtime(start_time)))

    #Options
    parser = argparse.ArgumentParser(usage="Look in process_traces.py to see supported arguments", add_help=False)

    #parser.add_argument("-i", dest="input_dir", default="/home/robin/datasets/moniotr")
    # parser.add_argument("-i", dest="input_dir", default="/home/robin/datasets/yourthings")
    parser.add_argument("-o", dest="output_dir", default="/home/robin/datasets/scratch/test/moniotr_test5")
    # parser.add_argument("-o", dest="output_dir", default="/home/robin/datasets/scratch/test/yourthings_test1")
    
    # parser.add_argument("-d", dest="device_list_path", default="/home/robin/datasets/moniotr/devices.json")
    # parser.add_argument("-d", dest="device_list_path", default="/home/robin/datasets/yourthings/devices.json")

    # experiment_list must be a comma-separated list of directories that are recursively traversed, looking for pcaps to process
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/t-philips-hub,iot-data/uk/smarter-coffee-mach,iot-data/uk/echoplus")
    # parser.add_argument("-l", dest="experiment_list", default="12")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/echoplus/volume")
    # parser.add_argument("-l", dest="experiment_list", default="../scratch/TEMP/tls_1_3.pcapng") # TLS 1.3 example trace
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/appletv/power/2019-04-26_12:59:01.247s.pcap") # has TLS 1.3 data
    
    # parser.add_argument("-l", dest="experiment_list", default="../scratch/TEMP/2019-04-26_12_23_35.222s.pcap") # spurious retransmits

    
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/echoplus")

    # interval tester 1
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/allure-speaker")
    
    # interval tester 2
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/echoplus")

    

    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/samsungtv-wired") # local_menu
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/blink-camera/alexa_watch")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/ring-doorbell/android_wan_watch")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/bosiwo-camera-wired")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/yi-camera")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/appletv")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/blink-security-hub")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/charger-camera")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/dlink-camera")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/echodot")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/echospot")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/firetv")
    
    
    
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach/alexa_on")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach/power")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach,iot-data/uk/ring-doorbell")
    # parser.add_argument("-l", dest="experiment_list", default="../scratch")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach/power,iot-data/uk/smarter-coffee-mach/android_wan_on")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach/")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach/power,iot-data/uk/smarter-coffee-mach/android_wan_on,iot-data/uk/smarter-coffee-mach/android_lan_on")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/magichome-strip/power,iot-data/uk/magichome-strip/android_wan_on,iot-data/uk/magichome-strip/android_lan_on")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/us/philips-bulb/power,iot-data/us/philips-bulb/android_wan_on,iot-data/us/philips-bulb/android_lan_on")
    # parser.add_argument("-l", dest="experiment_list", default="../thebasement/wemo_initial")
    # # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach/power,iot-idle/uk/smarter-coffee-mach,iot-data/uk/smarter-coffee-mach/android_wan_on,iot-data/uk/smarter-coffee-mach/android_lan_on")
    
    parser.add_argument("-i", dest="input_dir", default="/home/robin/datasets/yourthings")
    parser.add_argument("-d", dest="device_list_path", default="/home/robin/datasets/yourthings/devices.json")
    # parser.add_argument("-l", dest="experiment_list", default="11/eth1-20180411.0000.1523422800") # small one at 76MB
    # parser.add_argument("-l", dest="experiment_list", default="11/eth1-20180411.2020.1523496000") # medium one at 181 MB # takes about 1 minute
    parser.add_argument("-l", dest="experiment_list", default="11/eth1-20180411.0055.1523426100") # big one at 227MB # takes about 1.5 minutes
    # parser.add_argument("-l", dest="experiment_list", default="11/eth1-20180411.0410.1523437800") # biggest one at 345 MB
     
    


    
    parser.add_argument("-v", dest="verbose", default=True)

    parser.add_argument("-p", dest="process_count", default=4)
    parser.add_argument("--override", dest="override_results", default=False)

    parser.add_argument("-h", dest="help", action="store_true", default=False)

    #Parse Arguments
    args = parser.parse_args()

    if args.help:
        print_usage(0)

    errors = False

    experiment_list = []
    if args.experiment_list is not None:
        experiment_list = args.experiment_list.split(",")
    
    if len(experiment_list) == 0: 
        errors = True
        print("Error: experiment list was empty!", file=sys.stderr)

    #check -i input_dir
    if args.input_dir == "":
        errors = True 
        print("Error: Pcap input directory (-i) required.", file=sys.stderr)
    elif Util.check_dir(args.input_dir, "Input pcap directory"):
        errors = True

    #check -i output_dir
    if args.output_dir == "":
        errors = True 
        print("Error: output directory (-o) required.", file=sys.stderr)
    elif Util.check_dir(args.output_dir, "Output directory"):
        errors = True

    device_list = []
    if args.device_list_path == "":
        errors = True 
        print("Error: device list (-d) required.", file=sys.stderr)
    else:
        if not os.path.isfile(args.device_list_path):
            errors = True
            print("Error: specified device list file does not exist. " + str(args.device_list_path), file=sys.stderr)
        else:
            with open(args.device_list_path, "r") as f:
                device_list = json.loads( f.read() )
                if len(device_list) == 0:
                    errors = True
                    print("Error: device list file was empty or not JSON. " + str(args.device_list_path), file=sys.stderr)
                else:
                    device_list = Device.DeviceList(device_list)

    if errors:
        print_usage(1)

    process_count = int(args.process_count)
    override_results = args.override_results
    verbose = args.verbose

    #Create the groups to run analysis with processes
    raw_files = [ [] for _ in range(process_count) ]

    # Split the pcap files into num_proc groups
    # TODO: adjust this logic for when we start processing actual batches
    def walk_directory( dir_path, output_list, output_index ):
        print("Walk dir " + dir_path)

        if os.path.isfile( dir_path ):
            raw_files[output_index].append( dir_path )
            output_index += 1
            if output_index >= process_count:
                output_index = 0

            return output_index 

        for root, dirs, files in os.walk(dir_path):
            for filename in files:
                if (filename.endswith(".pcap") and not filename.startswith(".")) or filename.endswith(".pcapng") or filename.startswith("eth"): # one of the datasets has pcaps without extensions but starts with "eth"
                    raw_files[output_index].append( os.path.join(root, filename) )
                    output_index += 1
                    if output_index >= process_count:
                        output_index = 0
            for dir in dirs:
                output_index = walk_directory( os.path.join(root, dir), raw_files, output_index )

            return output_index

    for experiment in experiment_list:
        walk_directory( args.input_dir + os.path.sep + experiment, raw_files, 0 )

    if override_results:
        if verbose:
            print("Clearing output directory %s" % args.output_dir)

        for root, dirs, files in os.walk( args.output_dir ):
            for f in files:
                os.unlink(os.path.join(root, f))
            for d in dirs:
                shutil.rmtree(os.path.join(root, d))

    gc.collect()

    if verbose:
        print("Analyzing input pcap files...")

    # TODO: refactor this into a proper class
    params = {
        "device_list": device_list,
        "output_dir": args.output_dir,
        "verbose": verbose
    }

    # run analysis with num_proc processes
    procs = []
    for pid, files in enumerate(raw_files):
        p = Process(target=run, args=(pid, files, params))
        procs.append(p)
        p.start()

    for p in procs:
        p.join()

    end_time = time.time()
    print("\nEnd time: %s" % time.strftime("%A %d %B %Y %H:%M:%S %Z", time.localtime(end_time)))

    #Calculate elapsed time
    sec = round(end_time - start_time)
    hrs = sec // 3600
    if hrs != 0:
        sec = sec - hrs * 3600

    minute = sec // 60
    if minute != 0:
        sec = sec - minute * 60

    print("Elapsed time: %s hours %s minutes %s seconds" % (hrs, minute, sec))
    if verbose:
        print("\nAnalysis finished.")


def run(pid, pcap_files, params):

    file_count = len(pcap_files)
    for idx, filepath in enumerate(pcap_files):
        print("P%s (%s/%s): Processing pcap file \"%s\"..." % (pid, idx + 1, file_count, filepath))
        # analyze_pcap(filepath, params)

        processor = TraceProcessor()
        processor.process_trace( filepath, params )
        # print("P%s (%s/%s): Done processing, closing pcap file \"%s\"..." % (pid, idx + 1, file_count, filepath))
        processor.close( filepath, params )
        # print("P%s (%s/%s): Done closing, releasing thread \"%s\"..." % (pid, idx + 1, file_count, filepath))
        gc.collect()

if __name__ == "__main__":
    main()
