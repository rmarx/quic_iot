import os
import json

from .ConnectionTracker import ConnectionTracker
from lib.models.Connection import Connection
from lib.processors.ConnectionStats import *

class TraceProcessor:

    def __init__(self):
        self.tracker = None

    def process_trace(self, trace_path, params):
        output_dir = params["output_dir"]
        device_list = params["device_list"]
        verbose = params["verbose"]

        self.tracker = ConnectionTracker()

        unprocessed_packet_count = 0

        
        if "yourthings" in trace_path:
            # the yourthings dataset is a weird one: large files and duplicate VLAN entries for each packet
            # we can't process them normally as we do smaller files, so we need to cut them down a bit by removing some hex-fields and removing newlines from the json
        
            # example of what we want to achieve:
            # tshark --no-duplicate-keys -Y "!(vlan)" -r /home/robin/datasets/yourthings/11/eth1-20180411.0000.1523422800 -T json | 
            # jq -c 'del(.[]."_source".layers?.tcp?."tcp.payload",.[]."_source".layers?.tcp?."tcp.options"?,.[]."_source".layers?.tcp?."tcp.segment_data"?,
            # .[]."_source".layers?.eth?."eth.dst_tree"?,.[]."_source".layers?.eth?."eth.src_tree"?)' > yourthingstestFull.json

            jqCommand = "jq -c 'del(.[].\"_source\".layers?.tcp?.\"tcp.payload\",.[].\"_source\".layers?.tcp?.\"tcp.options\"?,.[].\"_source\".layers?.tcp?.\"tcp.segment_data\"?,.[].\"_source\".layers?.eth?.\"eth.dst_tree\"?,.[].\"_source\".layers?.eth?.\"eth.src_tree\"?)'"

            frames = json.loads( str(os.popen(("tshark --no-duplicate-keys -Y \"!(vlan)\" -r %s -T json | " + jqCommand) % trace_path).read()) )
        else:
            # add -x to include raw hex data (probably not the best idea, increases file size by a -huge- amount)
            frames = json.loads( str(os.popen("tshark --no-duplicate-keys -r %s -T json" % trace_path).read()) )

        # have tshark output in a newline-delimited JSON format (the -T ek) so we can parse packet-by-packet in a streaming fashion
        # packets = str(os.popen("tshark -r %s -T ek -x" % trace_path).read()).splitlines()
        # packets = str(os.popen("tshark -r %s -T ek" % trace_path).read()).splitlines()
            # packet = json.loads(packetstring)
        # turns out that this format deals badly with repeated fields; more specifically TLS records are all grouped up badly and non-discernible
        # so we had to switch to using pure JSON output instead
        
        for frame in frames:

            packet = frame["_source"]

            # TODO: update flow to also be able to track ICMP PING packets (have no ports)
            connection = self.tracker.find_connection(packet)

            if connection is None: # no connection available means we can't/don't want to track this type of packet at this time, so continue to the next
                unprocessed_packet_count += 1
                if verbose:
                    if "layers" in packet:
                        expected = ["llc", "arp", "eapol", "icmp", "igmp", "icmpv6", "mdns"]
                        if not any( protocol in packet["layers"] for protocol in expected ):
                            print("TraceProcessor:process_trace: unexpected packet type : " + str(packet["layers"].keys()))
                    else:
                        # due to using the elastic-search JSON output, we sometimes get weird events in the output that we want to ignore:
                        # {'index': {'_index': 'packets-2019-04-26', '_type': 'doc'}}
                        expected = ["index"]
                        if not any( protocol in packet for protocol in expected ):
                            print("TraceProcessor:process_trace: unexpected event type : " + str(packet))
                        else:
                            unprocessed_packet_count -= 1 # isn't a real packet, so don't count 
                continue

            interpreters = connection.get_interpreters()
            if len(interpreters) == 0:
                # new connection that was just added, need to add interpreters
                # if verbose:
                #    print("TraceProcessor: new connection found : {}".format(connection) )

                interpreters.append( ConnectionEstablishedTracker() )
                interpreters.append( ConnectionClosedTracker() )
                interpreters.append( PacketCounter() )
                interpreters.append( ActivityTracker() )
                interpreters.append( RetransmissionTracker() )
                interpreters.append( HandshakeTracker() )
                interpreters.append( RTTTracker() )

            for interpreter in interpreters:
                interpreter.update(connection, packet)
        # except Exception as e:
        #     print("Unexpected error parsing pcap, continuing {} : {}".format(trace_path, e))
        #     # return
        #     # pass
       


        # if ( len(unique_ips) == 0 ):
        #     print( "Added to empty traces %s" % trace_path )
        #     # print( infoLists.emptyTraces )

        # print("Unmatched packet count {}".format(unprocessed_packet_count))

        # output = tracker.serialize()
        # output["unmatched_packet_count"] = unprocessed_packet_count

        # print( json.dumps(output) )

        # first_ip = next(iter(unique_ips), None)
        # first_mac = next(iter(unique_macs), None)

        # device = device_list.find_by_ip( first_ip )
        # if device is None:
        #     device = device_list.find_by_mac( first_mac )

        # if device is not None:

        #     if verbose:
        #         print("------------------")
        #         print("Device found for ip or mac! %s " % device.name )
        #         print("------------------")

        #     output_file_path = os.path.join(output_dir, device.name + ".json")
        #     print("Writing to " + str(output_file_path))

        #     # output_file = "/home/robin/datasets/scratch/test/test.txt"
        #     with open( output_file_path, 'a' ) as testfile:
        #         # for i in range(0, 10000):
        #         #     testfile.write( str(pid) + "." )
        #         # testfile.write("\n")

        #         #testfile.write("abcdefghijklmnopqrstuvwxyz " + json.dumps(c.__dict__, separators=(",",":")) + "\n")
        #         # testfile.write( json.dumps(c.__dict__, separators=(",",":")) + "\n" )
        #         # print( json.dumps(c.__dict__) )
        #         print( 'test' )

        # else:
        #     print( "No device found for mac or IP %s / %s" % (first_ip, first_mac) )

    def close(self, trace_path, params):

        output_dir = params["output_dir"]
        device_list = params["device_list"]
        verbose = params["verbose"]

         # all packets in this trace have been processed.
        # now we want to group connections per device and write them to per-device files
        connections = self.tracker.get_connections()

        deviceMap = {}

        for connection in connections:
            device = device_list.find_by_connection(connection)
            if device is not None:
                if device.type != "device":
                    print("Device found that's not device! {} from {}".format(device.__dict__, connection.__dict__))
                    # exit() # bad in moniotr traces, but somewhat normal in yourthings for example... 
                if device.name not in deviceMap:
                    deviceMap[ device.name ] = []

                deviceMap[ device.name ].append( connection )
            else:
                print("TraceProcessor: ERROR: no device found for connection! {} {} {}".format(connection, connection.mac1, connection.mac2) )
                
                if "unknown" not in deviceMap:
                    deviceMap[ "unknown" ] = []

                deviceMap[ "unknown" ].append( connection )


        for device_name in deviceMap:
            device_output_path = os.path.join(output_dir, device_name + ".json")
            if verbose:
                print("Writing information for device {} to file {}".format(device_name, device_output_path))

            output = {}
            connectionList = []

            for connection in deviceMap[ device_name ]:
                connectionInfo = {}
                connection.serialize(connectionInfo)

                for interpreter in connection.get_interpreters():
                    interpreter.serialize(connectionInfo)

                connectionList.append(connectionInfo)

            device = device_list.find_by_name(device_name)
            if device is not None:
                device_type = device.type
            else:
                device_type = "unknown"
    
            output = { 
                "trace": trace_path,
                "device": {
                    "name": device_name,
                    "type": device_type
                },
                "connections": connectionList 
            }

            device = device_list.find_by_name(device_name)
            if device is not None:
                if device.ip is not None:
                    output["device"]["ip"] = device.ip
                if device.mac is not None:
                    output["device"]["mac"] = device.mac 

            # print( json.dumps( output ) )
            with open( device_output_path, 'a' ) as output_file:
                # for i in range(0, 10000):
                #     testfile.write( str(pid) + "." )
                # testfile.write("\n")

                #testfile.write("abcdefghijklmnopqrstuvwxyz " + json.dumps(c.__dict__, separators=(",",":")) + "\n")
                # output_file.write( json.dumps(c.__dict__, separators=(",",":")) + "\n" )
                # print( json.dumps(c.__dict__) )
                output_file.write( json.dumps(output) + "\n" )