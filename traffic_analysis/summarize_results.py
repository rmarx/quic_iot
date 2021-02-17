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
from lib.analyzers.DeviceAnalyzer import DeviceAnalyzer

def main():
    global device_list, verbose

    start_time = time.time()

    print("Summarizing results")
    print("Start time: %s\n" % time.strftime("%A %d %B %Y %H:%M:%S %Z", time.localtime(start_time)))

    #Options
    parser = argparse.ArgumentParser(usage="Look in summarize_results.py to see supported arguments", add_help=False)

    parser.add_argument("-i", dest="input_dir", default="/home/robin/datasets/scratch/results")
    parser.add_argument("-o", dest="output_dir", default="/home/robin/datasets/scratch/summary")
    
    parser.add_argument("-v", dest="verbose", default=True)

    parser.add_argument("-p", dest="process_count", default=1)
    parser.add_argument("--override", dest="override_results", default=True)

    parser.add_argument("-h", dest="help", action="store_true", default=False)

    #Parse Arguments
    args = parser.parse_args()

    if args.help:
        print_usage(0)

    errors = False

    #check -i input_dir
    if args.input_dir == "":
        errors = True 
        print("Error: Results input directory (-i) required.", file=sys.stderr)
    elif check_dir(args.input_dir, "Results directory"):
        errors = True

    #check -i output_dir
    if args.output_dir == "":
        errors = True 
        print("Error: output directory (-o) required.", file=sys.stderr)
    elif check_dir(args.output_dir, "Output directory"):
        errors = True

    if errors:
        print_usage(1)

    process_count = args.process_count
    override_results = args.override_results
    verbose = args.verbose

    #Create the groups to run analysis with processes
    raw_files = [ [] for _ in range(process_count) ]

    # Split the pcap files into num_proc groups
    # TODO: adjust this logic for when we start processing actual batches
    def walk_directory( dir_path, output_list, output_index ):
        print("Walk dir " + dir_path + "," + str(output_index))
        for root, dirs, files in os.walk(dir_path):
            for filename in files:
                if filename.endswith(".json"):
                    raw_files[output_index].append( os.path.join(root, filename) )
                    output_index += 1
                    if output_index >= process_count:
                        output_index = 0
            for dir in dirs:
                output_index = walk_directory( os.path.join(root, dir), raw_files, output_index )

            return output_index

    walk_directory( args.input_dir, raw_files, 0 )

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
        print("Summarizing device result files...")

    # TODO: refactor this into a proper class
    params = {
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
        print("\nSummary finished.")


def run(pid, pcap_files, params):

    file_count = len(pcap_files)
    for idx, filepath in enumerate(pcap_files):
        print("P%s (%s/%s): Processing device results file \"%s\"..." % (pid, idx + 1, file_count, filepath))
        
        analyzer = DeviceAnalyzer()
        analyzer.analyze_device( filepath, params )
        analyzer.close( filepath, params )

        gc.collect()

if __name__ == "__main__":
    main()
