# some code inspired by https://github.com/NEU-SNS/intl-iot/tree/master/destination

""" Scripts processing pcap files and generating text output and figures """

import argparse
import os
import re
import sys
from multiprocessing import Process
import gc
import time
from random import random
import json

from util.InfoLists import InfoLists 
from util.Connection import Connection
import util.Device as Device
import multiprocessing
import queue

# import pyshark

#from trafficAnalyzer import *  #Import statement below, after package files are checked

#File paths
PATH = sys.argv[0]
DEST_DIR = os.path.dirname(PATH)
if DEST_DIR == "":
    DEST_DIR = "."

# from trafficAnalyzer import *
# from trafficAnalyzer import Constants as c

args = [] #Main args
plots = [] #Graph args
devices = None

yunowork2 = None


# #isError is either 0 or 1
# def print_usage(is_error):
#     #print(c.USAGE_STM, file=sys.stderr) if is_error else print(c.USAGE_STM)
#     exit(is_error)


def check_dir(direc, description=""):
    errors = False
    if direc == "":
        direc = "."
    if not os.path.isdir(direc):
        errors = True
        if description == "":
            print("Error: The \"%s\" directory is missing." % (direc), file=sys.stderr)
        else:
            print("Error: %s \"%s\" is not a directory." % (description, direc), file=sys.stderr)
    else:
        if not os.access(direc, os.R_OK):
            errors = True
            print("Error: The directory \"%s\" does not have read permission." % (direc), file=sys.stderr)
        if not os.access(direc, os.X_OK):
            errors = True
            print("Error: The directory \"%s\" does not have execute permission." % (direc), file=sys.stderr)

    return errors


# def check_files(direc, files, is_geo, description=""):
#     errors = check_dir(direc)
#     if not errors:
#         missing_file = False
#         for f in files:
#             if not os.path.isfile(f):
#                 missing_file = errors = True
#                 if description == "":
#                     print(c.MISSING % (f, "file"), file=sys.stderr)
#                 else:
#                     print(c.INVAL % (description, f, "file"), file=sys.stderr)
#             elif not os.access(f, os.R_OK):
#                 errors = True
#                 print(c.NO_PERM % ("file", f, "read"), file=sys.stderr)

#         if missing_file and is_geo:
#             print(c.DOWNLOAD_DB, file=sys.stderr)

#     return errors


def main():
    global args, plots, devices, yunowork2

    start_time = time.time()

    print("Performing destination analysis...")
    print("Running %s..." % PATH)
    print("Start time: %s\n" % time.strftime("%A %d %B %Y %H:%M:%S %Z", time.localtime(start_time)))

    # #Check that GeoLite2 databases and aux scripts exist and have proper permissions
    # check_files(GEO_DIR, [GEO_DB_CITY, GEO_DB_COUNTRY], True)
    # check_files(AUX_DIR, [IP_TO_ORG, IP_TO_COUNTRY], False)

    HOWTO = """
    Look in main.py to see supported arguments
    """

    #Options
    parser = argparse.ArgumentParser(usage=HOWTO, add_help=False)

    parser.add_argument("-i", dest="input_dir", default="/home/robin/datasets/moniotr")
    parser.add_argument("-o", dest="output_dir", default="/home/robin/datasets/scratch/test")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach/power,iot-idle/uk/smarter-coffee-mach,iot-data/uk/smarter-coffee-mach/android_wan_on,iot-data/uk/smarter-coffee-mach/android_lan_on")
    
    parser.add_argument("-d", dest="device_list_file", default="/home/robin/datasets/moniotr/devices.json")

    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach/power")
    parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach/power,iot-data/uk/smarter-coffee-mach/android_wan_on")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/smarter-coffee-mach/power,iot-data/uk/smarter-coffee-mach/android_wan_on,iot-data/uk/smarter-coffee-mach/android_lan_on")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/uk/magichome-strip/power,iot-data/uk/magichome-strip/android_wan_on,iot-data/uk/magichome-strip/android_lan_on")
    # parser.add_argument("-l", dest="experiment_list", default="iot-data/us/philips-bulb/power,iot-data/us/philips-bulb/android_wan_on,iot-data/us/philips-bulb/android_lan_on")
    # parser.add_argument("-l", dest="experiment_list", default="../thebasement/wemo_initial")
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
    elif check_dir(args.input_dir, "Input pcap directory"):
        errors = True

    #check -i output_dir
    if args.output_dir == "":
        errors = True 
        print("Error: output directory (-o) required.", file=sys.stderr)
    elif check_dir(args.output_dir, "Output pcap directory"):
        errors = True

    device_list = []
    if args.device_list_file == "":
        errors = True 
        print("Error: device list (-d) required.", file=sys.stderr)
    else:
        with open(args.device_list_file, "r") as f:
            device_list = json.loads( f.read() )
            device_list = Device.DeviceList(device_list)

    # device_list_test
    yunowork2 = device_list



    def testGlobal():
        global yunowork2
        print( "THE FIRST DEVICE" + str(yunowork2.list[0]) )

    testGlobal()

    if errors:
        print_usage(1)

    # for device in device_list.list:
    #     print( device.type + device.mac + device.ip )

    # print ( device_list.find_by_mac("18:b4:30:c8:d8:28") )
    # print ( device_list.find_by_name("nest-tstat").__dict__ )
    # print ( device_list.find_by_name("non-existent") )

    # exit()

    # TODO: adjust this logic for when we start processing actual batches
    num_proc = 1
    clear_files = True # will first remove the files to make sure we don't have old results mixing with new 

    #Create the groups to run analysis with processes
    raw_files = [ [] for _ in range(num_proc) ]

    index = 0
    # Split the pcap files into num_proc groups
    # TODO: adjust this logic for when we start processing actual batches
    for experiment in experiment_list:
        for root, dirs, files in os.walk(args.input_dir + os.path.sep + experiment):
            for filename in files:
                if filename.endswith(".pcap") and not filename.startswith("."):
                    raw_files[index].append(root + "/" + filename)
                    index += 1
                    if index >= num_proc:
                        index = 0

    gc.collect()

    # c = Connection( "127.0.0.1", 32, "127.0.0.2", 33 )
    # print( type(c) )
    # print( type(c) is Connection )
    # exit() 

    print("Analyzing input pcap files...")
    infoLists = InfoLists()
    messageQueue = multiprocessing.Queue()

    params = {
        "clear_file_first": clear_files,
        "device_list": device_list
    }

    # run analysis with num_proc processes
    procs = []
    for pid, files in enumerate(raw_files):
        p = Process(target=run, args=(pid, files, params, messageQueue))
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
    print("\nAnalysis finished.")

    print("Received events")
    while True:
        try:
            evt = messageQueue.get_nowait()
            print( type(evt) )
            print( str(evt.port1) + " " + str(evt.port2) )
        except queue.Empty:
            print("QUEUE IS EMPTY NOW!")
            break

    print("Empty traces:")
    # for n in infoLists.emptyTraces.queue:
    #     print( n )
    print( infoLists.emptyTraces )

    # with open("/home/robin/datasets/scratch/test/test.txt", "r") as sf:
    #     for line in sf.readlines():
    #         line = line.strip()
    #         print( json.loads(line) )


def run(pid, pcap_files, params, messageQueue):
    print(" RUN WITH PARAMS ") 
    print( params )

    files_len = len(pcap_files)
    for idx, f in enumerate(pcap_files):
        perform_analysis(pid, idx + 1, files_len, f, params, messageQueue)
        gc.collect()


def perform_analysis(pid, idx, files_len, pcap_path, params, messageQueue):
    print("P%s (%s/%s): Processing pcap file \"%s\"..." % (pid, idx, files_len, pcap_path))

    # print(" RUN WITH PARAMS 2 ") 
    # print( params["device_list"].__dict__ )

    unique_ips = set()
    unique_macs = set()

    packets = str(os.popen("tshark -r %s -T ek" % pcap_path).read()).splitlines()
    for packetstring in packets:
        # print("Loading %s" % packetstring)
        packet = json.loads(packetstring)
        
        if ( "layers" in packet and "eth" in packet["layers"] ):
            unique_macs.add( packet["layers"]["eth"]['eth_eth_src'] )
            unique_macs.add( packet["layers"]["eth"]['eth_eth_dst'] )

        if ( "layers" in packet and "ip" in packet["layers"] ):
            unique_ips.add( packet["layers"]["ip"]['ip.src'] )
            unique_ips.add( packet["layers"]["ip"]['ip.dst'] )

        # if packetstring.find("SYN") >= 0:
        if "layers" in packet and "tcp" in packet["layers"] and "tcp.flags.syn_raw" in packet["layers"]["tcp"]:
            if packet["layers"]["tcp"]["tcp.flags.syn_raw"] == "1" and packet["layers"]["tcp"]["tcp.flags.ack_raw"] != "1":
                print( "TCP SYN %s -> %s" % (packet["layers"]["ip"]['ip.src'], packet["layers"]["ip"]['ip.dst']) )
            elif packet["layers"]["tcp"]["tcp.flags.syn_raw"] == "1" and packet["layers"]["tcp"]["tcp.flags.ack_raw"] == "1": 
                print( "TCP SYN/ACK %s -> %s" % (packet["layers"]["ip"]['ip.src'], packet["layers"]["ip"]['ip.dst']) )
    
    c = Connection("127.0.0.1", pid, "127.0.0.2", idx)
    messageQueue.put( c )

    if ( len(unique_ips) == 0 ):
        print( "Added to empty traces %s" % pcap_path )
        # print( infoLists.emptyTraces )

    print( unique_ips )
    print( unique_macs )

    global yunowork2
    first_ip = next(iter(unique_ips), None)
    first_mac = next(iter(unique_macs), None)

    device = yunowork2.find_by_ip( first_ip )
    if device is None:
        device = yunowork2.find_by_mac( first_mac )

    if device is not None:

        print("------------------")
        print("Device found for ip or mac! %s " % device.name )
        print("------------------")

        output_file_path = output_dir + os.path.sep + device.name + ".json"
        if params.clear_file_first:
            if os.path.exists(output_file_path):
                os.remove(output_file_path)

        # output_file = "/home/robin/datasets/scratch/test/test.txt"
        with open( output_file_path, 'a' ) as testfile:
            # for i in range(0, 10000):
            #     testfile.write( str(pid) + "." )
            # testfile.write("\n")

            #testfile.write("abcdefghijklmnopqrstuvwxyz " + json.dumps(c.__dict__, separators=(",",":")) + "\n")
            testfile.write( json.dumps(c.__dict__, separators=(",",":")) + "\n" )
            print( json.dumps(c.__dict__) )

    else:
        print( "No device found for mac or IP %s / %s" % (first_ip, first_mac) )

        # hosts = str(os.popen("tshark -r %s -Y \"dns&&dns.a\" -T fields -e dns.qry.name -e dns.a" % pcap_path).read()).splitlines()
        # #make dictionary of ip to host from DNS requests
        # ip_host = {} #dictionary of destination IP to hostname
        # for line in hosts: #load ip_host
        #     #line[0] is host, line[1] contains IPs that resolve to host
        #     print(line)

        #     line = line.split("\t")
        #     ips = line[1].split(",")
        #     for ip in ips:
        #         ip_host[ip] = line[0]

        #  time.sleep( random() * 3 )
        # cap = pyshark.FileCapture(pcap_file, use_json=True)
        
        # Utils.sysUsage("PCAP file loading")

        # cap.close()
        # base_ts = 0
        # try:
        #     if args.no_time_shift:
        #         cap[0]
        #     else:
        #         base_ts = float(cap[0].frame_info.time_epoch)
        # except KeyError:
        #     print(c.NO_PCKT % pcap_file, file=sys.stderr)
        #     return

        # node_id = Node.NodeId(args.mac_addr, args.ip_addr)
        # node_stats = Node.NodeStats(node_id, base_ts, devices)

        # print("  P%s: Processing packets..." % pid)
        # try:
        #     for packet in cap:
        #         node_stats.processPacket(packet)
        # except:
        #     print("  %sP%s: Error: There is something wrong with \"%s\". Skipping file.%s"
        #           % (RED, pid, pcap_file, END), file=sys.stderr)
        #     return

        # del cap

        # Utils.sysUsage("Packets processed")

        # print("  P%s: Mapping IP to host..." % pid)
        # ip_map = IP.IPMapping()
        # if args.hosts_dir != "":
        #     host_file = args.hosts_dir + "/" + os.path.basename(pcap_file)[:-4] + "txt"
        #     ip_map.extractFromFile(pcap_file, host_file)
        # else:
        #     ip_map.extractFromFile(pcap_file)

        # ip_map.loadOrgMapping(IP_TO_ORG)
        # ip_map.loadCountryMapping(IP_TO_COUNTRY)

        # Utils.sysUsage("TShark hosts loaded")

        # print("  P%s: Generating CSV output..." % pid)
        # de = DataPresentation.DomainExport(node_stats.stats.stats, ip_map, GEO_DB_CITY, GEO_DB_COUNTRY)
        # de.loadDiffIPFor("eth") if args.find_diff else de.loadIPFor("eth")
        # de.loadDomains(args.dev, args.lab, args.experiment, args.network, pcap_file, str(base_ts))
        # de.exportDataRows(args.out_file)

        # print("  P%s: Analyzed data from \"%s\" successfully written to \"%s\""
        #       % (pid, pcap_file, args.out_file))

        # Utils.sysUsage("Data exported")

        # if len(plots) != 0:
        #     print("  P%s: Generating plots..." % pid)
        #     pm = DataPresentation.PlotManager(node_stats.stats.stats, plots)
        #     pm.ipMap = ip_map
        #     pm.generatePlot(pid, pcap_file, args.fig_dir, GEO_DB_CITY, GEO_DB_COUNTRY)
        #     Utils.sysUsage("Plots generated")


if __name__ == "__main__":
    main()
