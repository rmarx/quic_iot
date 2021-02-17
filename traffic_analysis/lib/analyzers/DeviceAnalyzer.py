import os
import json

from lib.models.Connection import Connection
from lib.models.Connection import ConnectionPhase
from lib.analyzers.ConnectionAnalyzers import *
from dotmap import DotMap

class DeviceAnalyzer:

    def __init__(self):
        self.analyzers = []

    def analyze_device(self, device_connections_path, params):
        output_dir = params["output_dir"]
        verbose = params["verbose"]

        # need a way to track connections over time
        # step 1: make a list of all connections based on timestamp? 
        # step 2: add connections to list, try to match each connection to a previous one
        # caveats:
        #   - what if a connection is closed and re-started?
        #       - maybe working with two lists: open connections and closed connections? 
        #       - if a connection is found that has opened=True and it was already in opened, force push to closed or something? 
        # so what we need is a chain of connections, where the first one is the one that opens, the last one closes
            # with that, we can aggregate data like bytes sent etc. over the connections 

        # NEW INSIGHT: Do we really need that for our purpose? and we can't really get this from the moniotr, since there we have multiple runs that can be combined with multiple power-on scenarios right?
        # concept of connection phases can be all we need
            # power-on/connection setup: helps determine how useful 0-RTT is as a whole + RTT 
            # connection re-use after interaction: helps determine if we can use the humaness thing
        # basically, we need to mainly know what happens after app interaction -> how many new connections setup, how many re-used, how much data exchanged, etc.
            # easy to know for moniotr, so let's start with that 
            # for yourthings, we need to find a different way of figuring that out
                # could be by looking for downtime in a connection (initial = startup, when it sends more data after a while=post-interaction)
                # could also be done by looking at traffic coming from one of the devices we know have apps on them in that dataset to try and determine


            # what we really need is to estimate the latency for the persistent connections
                # if we have their power_on, can estimate from there
                # if not, we need to observe TCP acks to estimate... urgh -> SEE IF EXPERT LAYER ALREADY HAS THIS: some include seq/ack analysis with an iRTT field

        # 1. figure out how many connections are local, how many are to the outside
        # 2. figure out how many connections are persistent
        # 3. figure out traffic burst durations

        with open(device_connections_path, 'r') as input_file:
            traces = input_file.read().splitlines()
        
            all_connections = []
            all_traces = []

            for tracestring in traces:
                trace = DotMap(json.loads(tracestring))

                all_traces.append( trace )

                # each trace contains a number of connections that were present in that trace
                # we want to track things across traces, so merge all the connections into one list (all_connections) and tag them with their (estimated) type/phase
                # trace
                #   - trace (original pcap path)
                #   - device (name, should be the same for all devices in this file)
                #   - connections
                #       - info
                #           - transport_protocol
                #           - endpoint1
                #               - ip
                #               - port
                #               - mac
                #           - endpoint2
                #       - connection_established, connection_closed, connection_close_type, estimated_RTT, packetcount, bytecount, starttime, endtime, duration

                if trace.trace and "moniotr" in trace.trace:
                    if "power" in trace.trace:
                        trace.phase = ConnectionPhase.INITIAL
                    elif "idle" in trace.trace:
                        trace.phase = ConnectionPhase.IDLE
                    else:
                        trace.phase = ConnectionPhase.INTERACTION
                else:
                    trace.phase = ConnectionPhase.UNKNOWN 

                for connection in trace.connections: # note: these are NOT instances of models.Connection

                    all_connections.append(connection)

                    connection.trace = trace.trace # track this per connection as well
                    connection.phase = trace.phase

            
            # now that we have the traces and connections prepared, we can analyze them in-depth
            self.analyzers = []
            self.analyzers.append ( ConnectionCounter() )
            self.analyzers.append( RTTTracker() )

            for analyzer in self.analyzers:
                analyzer.update( all_traces, all_connections )

            
            output = {}
            output["device"] = trace.device # should be the same for all traces in the input anyway

            for analyzer in self.analyzers:
                analyzer.serialize(output)

            print("analysis for {} : {}".format(trace.device, json.dumps(output)) )

            device_output_path = os.path.join( output_dir, trace.device + ".json" )

            with open( device_output_path, 'a' ) as output_file:
                output_file.write( json.dumps(output) + "\n" )


    def close(self, device_connections_path, params):
        output_dir = params["output_dir"]
        verbose = params["verbose"]

            

        print("DeviceAnalyzer:close : TODO : IMPLEMENT")