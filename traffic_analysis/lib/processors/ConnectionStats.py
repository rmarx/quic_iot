from enum import Enum
import kmeans1d
import statistics 
import json

from lib.models.Connection import Connection

# class DurationTracker:
#     def __init__(self):
#         self.earliest = 0
#         self.latest = 0
    
#     def update(self, connection, packet):
#         if self.earliest == 0:
#             self.earliest = float(packet["layers"]["frame"]["frame.time_epoch"])
#         else:
#             self.latest = float(packet["layers"]["frame"]["frame.time_epoch"])

#     def serialize(self, output):
#         output["starttime"] = self.earliest
#         output["endtime"] = self.latest
#         output["duration"] = self.latest - self.earliest

class TLSRecordType(Enum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    HEARTBEAT = 24
    UNKNOWN = 666

# http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/
# https://tools.ietf.org/html/rfc8446#section-4
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
class TLSHandshakeType(Enum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5 # TLS 1.3
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    CERTIFICATE_URL = 21
    CERTIFICATE_STATUS = 22
    SUPPLEMENTAL_DATA = 23
    KEY_UPDATE = 24 # TLS 1.3
    COMPRESSED_CERTIFICATE = 25
    EKT_KEY = 26
    MESSAGE_HASH = 254 # TLS 1.3
    UNKNOWN = 666


class TLSRecordInfo:
    def __init__(self):
        self.time = -1
        self.record_type = TLSRecordType.UNKNOWN.name
        self.handshake_type = TLSHandshakeType.UNKNOWN.name
        self.length = -1

    def toJSON(self):
        return self.__dict__

class HandshakeTracker:
    def __init__(self):
        self.tcpHandshakePackets = {}
        self.tlsRecords = {}

        self.ALPNs = {}
        self.tlsVersion = {}

        self.clientHelloSeen = False
        self.applicationDataCount = 0

        self.resumedSession = False
    
    def extractRecords(self, rawRecords):
        output = []

        # each of these fields can either be an object, array or string: deal with all possibilities
        # we get passed in the top-level "tls" field as "rawRecords"
        # tls: [
        #   "tls.record" : [
        #       "tls.record.OTHER_FIELDS": val
        #   ]
        # ]

        # inspired by https://github.com/quiclog/qvis/blob/master/visualizations/src/components/filemanager/pcapconverter/tcptoqlog.ts#L243
        if isinstance(rawRecords, (list, tuple)):
            if( len(rawRecords) == 0 ):
                print("ConnectionStats:extractRecords: tls was empty list... ignoring")
                raise Exception("TODO: REMOVE: ConnectionStats:extractRecords: tls was empty list... ignoring")
            else:
                for rawRecord in rawRecords:
                    if "tls.record" not in rawRecord:
                        if "tls.record.length" in rawRecord:
                            # there is no separate tls.record entry
                            output.append( rawRecord )
                        elif len(rawRecord) == 0: # sometimes, it's just an empty object {} for some reason
                            pass
                        elif "Ignored Unknown Record" in rawRecord:
                            # sometimes the record was just ignored, so we ignore this as well since there's no more info to be had
                            # this is sometimes the case with partial/spurious TCP retransmits
                            pass
                        else:
                            print("ConnectionStats:extractRecords: no tls.record or tls.record.length in rawRecord")
                            print( json.dumps(rawRecords) )
                            raise Exception("TODO: REMOVE: ConnectionStats:extractRecords: no tls.record or tls.record.length in rawRecord")

                    else:
                        realRecords = rawRecord["tls.record"]
                        if isinstance(realRecords, (list, tuple)):
                            if len(realRecords) == 0:
                                print("ConnectionStats:extractRecords: tls records was empty list... ignoring")
                                print( json.dumps(rawRecord) )
                                raise Exception("TODO: REMOVE: ConnectionStats:extractRecords: tls records was empty list... ignoring")
                            else:
                                for record in realRecords:
                                    output.extend( self.extractRecords(record) )
                        else:
                            output.append( realRecords ) # is just one record, directly usable
        else:  
            if "tls.record" in rawRecords:
                if isinstance(rawRecords["tls.record"], (list, tuple)):
                    output = rawRecords["tls.record"]
                else:
                    output.append( rawRecords["tls.record"] ) # single entry
            else:
                if "tls.record.length" in rawRecords:
                    # there is no separate tls.record entry, the record is directly inside the "tls" key for some reason
                    output.append( rawRecords )
                elif isinstance(rawRecords, str) and rawRecords == "Transport Layer Security":
                    # for some reason, sometimes it's just a string... ignore this
                    pass
                elif "Ignored Unknown Record" in rawRecords:
                    # sometimes the record was just ignored, so we ignore this as well since there's no more info to be had
                    # this is sometimes the case with partial/spurious TCP retransmits
                    pass
                elif len(rawRecords) == 1 and "tls.record.version" in rawRecords and rawRecords["tls.record.version"] == "0x00000002":
                    # the full record is just {"tls.record.version": "0x00000002"}
                    # this indicates SSLv2, which we don't support
                    self.tlsVersion = "SSLv2"
                    pass
                else:
                    print("ConnectionStats:extractRecords: no tls.record in tls object...ignoring")
                    print( json.dumps(rawRecords) )
                    raise Exception("TODO: REMOVE: ConnectionStats:extractRecords: no tls.record in tls object...ignoring")

        return output

    def update(self, connection, packet):
        # want to keep tracking of timings for TCP SYN, SYN/ACK
        # and for TLS ClientHello, ServerHello, ClientFinished, ServerFinished, first appdata sent, first appdata reply received
        src_ip = "INVALID_IP"
        time = float(packet["layers"]["frame"]["frame.time_epoch"])

        if "ip" in packet["layers"]:
            src_ip = packet["layers"]["ip"]['ip.src']

            if src_ip not in self.tlsRecords:
                self.tcpHandshakePackets[src_ip] = []
                self.tlsRecords[src_ip] = []
                self.tlsVersion[src_ip] = []

        if "tcp" in packet["layers"]:
            if "tcp.flags.syn_raw" in packet["layers"]["tcp"]:
                if packet["layers"]["tcp"]["tcp.flags.syn_raw"] == "1" and packet["layers"]["tcp"]["tcp.flags.ack_raw"] != "1":
                    self.tcpHandshakePackets[src_ip].append( { "type": "TCP_SYN", "time": float(packet["layers"]["frame"]["frame.time_epoch"]), "length": packet["layers"]["tcp"]["tcp_tcp_len"] } )
                elif packet["layers"]["tcp"]["tcp.flags.syn_raw"] == "1" and packet["layers"]["tcp"]["tcp.flags.ack_raw"] == "1": 
                    self.tcpHandshakePackets[src_ip].append( { "type": "TCP_SYNACK", "time": float(packet["layers"]["frame"]["frame.time_epoch"]), "length": packet["layers"]["tcp"]["tcp_tcp_len"] } )

        if "tls" in packet["layers"]:

            # wireshark output is wildly inconsistent.
            # sometimes a tls entry is a string, an array or an object
            # so we need a way to order information so we can process the records in a consistent fashion

            tls_records = self.extractRecords( packet["layers"]["tls"] )

            # print("PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP")
            # # print( json.dumps(tls_records) )
            # print( len(tls_records) )
            # print("PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP")

            for record in tls_records:
                if len(record) == 0: # for some reason, sometimes the TLS entry is just an empty dict. len() lets us check for that
                    print("ConnectionStats:HandshakeTracker : empty tls record!")
                    print(json.dumps(packet["layers"]["tls"]))
                    raise Exception("ConnectionStats:HandshakeTracker : empty tls record!")
                    continue

                record_type_key = "tls.record.content_type"

                if "tls.record.content_type" not in record:
                    if "tls.record.opaque_type" in record:
                        record_type_key = "tls.record.opaque_type"
                    elif len(record) == 1 and "tls.record.version" in record and record["tls.record.version"] == "0x00000002":
                        # the full record is just {"tls.record.version": "0x00000002"}
                        # this indicates SSLv2, which we don't support
                        self.tlsVersion = "SSLv2"
                        continue
                    else:
                        print("ConnectionStats:HandshakeTracker : no tls.record.content_type in record!")
                        print(json.dumps(record))
                        raise Exception("ConnectionStats:HandshakeTracker : no tls.record.content_type in record!")

                if "tls.record.version" in record:
                    # tls versions are weird beasts
                    # e.g., most handshakes start by indicating version 0x301 (TLS 1.0) in their ClientHello, even if it's really 1.2 or 1.3
                    # then, for 1.3's middlebox fooling shenanigans, it always claims to be TLS 1.2, and we need to check for the supported_versions extension below to see if it's really 1.3
                    # not quite helpfully, wireshark doesn't provide us a field with the "real" version, so we're left guessing
                    # for robustness, we approach this as a Dict of unique values with a counter indicating when they were added
                    # and leave the interpreter to have logic to e.g., look for the highest/last value

                    # this code doesn't work...
                    # if src_ip in self.tlsVersion and self.tlsVersion[src_ip] != record["tls.record.version"]:
                    #     print("TLSTracker: already had a registered version, which is now changed! {} -> {} ".format(self.tlsVersion[src_ip], record["tls.record.version"]) )
                    #     raise Exception("TLSTracker: already had a registered version, which is now changed!")

                    if record["tls.record.version"] not in self.tlsVersion[src_ip]:
                        self.tlsVersion[src_ip].append( record["tls.record.version"] )

                        print("TLS VERSIONS {}".format(self.tlsVersion))


                record_type = int(record[record_type_key])

                if record_type == TLSRecordType.HANDSHAKE.value:
                    if "tls.handshake" not in record:
                        print("ConnectionStats:HandshakeTracker : no tls.handshake in record!")
                        print(json.dumps(record))
                        raise Exception("ConnectionStats:HandshakeTracker : no tls.handshake in record!")

                    if record["tls.handshake"] == "":
                        # for encrypted handshake message (e.g., after a resumed TLS 1.2 session or by default in TLS 1.3), this entry is sometimes present, but empty, so skip
                        continue

                    handshake_records = record["tls.handshake"]

                    # in the case of re-assembled TLS records (e.g., split across multiple TCP packets)
                    # tshark outputs them as a single record of e.g., type HANDSHAKE instead of actually splitting them up... urgh
                    # but tls.handshake is a list containing the real records...

                    real_handshake_records = []
                    if isinstance(handshake_records, (list, tuple)):
                        real_handshake_records = handshake_records
                    else:
                        real_handshake_records.append( handshake_records )

                    for handshake_record in real_handshake_records:

                        if "tls.handshake.type" not in handshake_record:
                            print("ConnectionStats:HandshakeTracker : no tls.handshake.type in record!")
                            print(json.dumps(packet["layers"]["tls"]))
                            raise Exception("ConnectionStats:HandshakeTracker : no tls.handshake.type in record!")

                        handshake_type = handshake_record["tls.handshake.type"]


                        print("ConnectionStats:HandshakeTracker : Handshake type found NUMERICAL {}".format(handshake_type))

                        recordInfo = TLSRecordInfo()
                        recordInfo.time = time
                        recordInfo.record_type = TLSRecordType.HANDSHAKE.name
                        recordInfo.handshake_type = TLSHandshakeType(int(handshake_type)).name

                        recordInfo.length = int(handshake_record["tls.handshake.length"]) # tls.record.length would be better, but records are not always correctly split out, see above

                        self.tlsRecords[src_ip].append( recordInfo.toJSON() )

                        print("ConnectionStats:HandshakeTracker : Handshake type found {}".format(TLSHandshakeType(int(handshake_type)).name))

                        if recordInfo.handshake_type == TLSHandshakeType.CLIENT_HELLO:
                            self.clientHelloSeen = True

                        # extensions are logged as keys beneath the tls.handshake object with somewhat weird names:
                        # e.g., Extension: supported_versions (len=7)
                        # or Extension: session_ticket (len=0)
                        # or Extension: key_share (len=38)
                        # each of them then has a child called tls.handshake.extension.type (numeric)
                        # then, inside, you typically again have unstructured keys for the real extesion object
                        # e.g., "Server Name Indication extension" containing keys like "tls.handshake.extensions_server_name"
                        # but it's again inconsistent: some extensions won't have the additional indirection

                        if "tls.handshake.session_id_length" in handshake_record:
                            if int(handshake_record["tls.handshake.session_id_length"]) > 0:
                                print("RESUMED SESSION FOUND!")
                                self.resumedSession = True
                            # some stacks set a 0-length session-id when not resuming... because logic, so just ignore that case
                            # else:
                            #     print("ConnectionStats:HandshakeTracker : Session id set, but 0-length... strange")
                            #     print( json.dumps(handshake_record) )
                            #     raise Exception("ConnectionStats:HandshakeTracker : Session id set, but 0-length... strange")

                        for key in handshake_record:
                            # "Extension: supported_versions (len=7)":{
                            #     "tls.handshake.extension.type_raw":
                            #     "tls.handshake.extension.type":"43",
                            #     "tls.handshake.extension.len":"7",
                            #     "tls.handshake.extensions.supported_versions_len":"6",
                            #     "tls.handshake.extensions.supported_version":[
                            #     "0x00007f1c",
                            #     "0x00007f1b",
                            #     "0x00007f1a"
                            #     ]
                            if key.startswith("Extension: supported_versions"):
                                # if this is present, we probably have TLS 1.3
                                if "tls.handshake.extensions.supported_version" not in handshake_record[key]:
                                    print("ConnectionStats:HandshakeTracker : no tls.handshake.extensions.supported_version in extension!")
                                    print(json.dumps(handshake_record))
                                    raise Exception("ConnectionStats:HandshakeTracker : no tls.handshake.extensions.supported_version in extension!")

                                print( "ConnectionStats:HandshakeTracker : probably TLS 1.3 found {}".format(handshake_record[key]["tls.handshake.extensions.supported_version"]) )
                                if isinstance(handshake_record[key]["tls.handshake.extensions.supported_version"], str):
                                    self.tlsVersion[src_ip] = [ handshake_record[key]["tls.handshake.extensions.supported_version"] ]
                                else: # it's an array, use it directly
                                    self.tlsVersion[src_ip] = handshake_record[key]["tls.handshake.extensions.supported_version"]

                                # raise Exception("ConnectionStats:HandshakeTracker : probably TLS 1.3 found!")

                            if key.startswith("Extension: application_layer_protocol_negotiation"):
                                
                                if src_ip not in self.ALPNs:
                                    self.ALPNs[src_ip] = []

                                if int(handshake_record[key]["tls.handshake.extension.len"]) > 0:
                                    # tls.handshake.extensions_alpn_str_len
                                    self.ALPNs[src_ip] = handshake_record[key]["tls.handshake.extensions_alpn_list"]["tls.handshake.extensions_alpn_str"]
                                    print("ALPN found: {}".format(self.ALPNs[src_ip]))
                                else:
                                    print( "ConnectionStats:HandshakeTracker : ALPN length 0 {} : {}".format(key, handshake_record[key]) )
                                    raise Exception("ConnectionStats:HandshakeTracker : ALPN! length 0")

                elif record_type == TLSRecordType.APPLICATION_DATA.value: 

                    # only want to log the first APP_DATA for each sender (all normal traffic is APP_DATA after all, so we'd log everything otherwise)
                    # so check if the last one added for each sender isn't already APP_DATA
                    if len(self.tlsRecords[src_ip]) > 0 and self.tlsRecords[src_ip][-1]["record_type"] is not TLSRecordType.APPLICATION_DATA.name:
                        recordInfo = TLSRecordInfo()
                        recordInfo.time = time
                        recordInfo.record_type = TLSRecordType.APPLICATION_DATA.name
                        recordInfo.length = int(record["tls.record.length"])

                        self.tlsRecords[src_ip].append( recordInfo.toJSON() )

                        self.applicationDataCount += 1

                elif record_type == TLSRecordType.ALERT.value: 
                    recordInfo = TLSRecordInfo()
                    recordInfo.time = time
                    recordInfo.record_type = TLSRecordType.ALERT.name
                    recordInfo.length = int(record["tls.record.length"])

                    self.tlsRecords[src_ip].append( recordInfo.toJSON() )

                else: 
                    recordInfo = TLSRecordInfo()
                    recordInfo.time = time
                    recordInfo.record_type = TLSRecordType(int(record_type)).name # TLSRecordType.ALERT.name
                    recordInfo.length = int(record["tls.record.length"])

                    self.tlsRecords[src_ip].append( recordInfo.toJSON() )



                # if "tls.record_content_type" in entry:
                #     # tls_tls_record_content_type
                #     # tls_tls_record_version
                #     # tls_tls_record_length


                #     # for some strange reason, sometimes wireshark has an array per field instead of just an array of full records under TLS
                #     # so it's 'tls_tls_record_content_type': ['23', '23'], 'tls_tls_record_length_raw': ['0001', '0028'], etc. 
                #     # I have no idea why this happens sometimes instead of having a tls_entries list... 
                #     # so we have to manually split these cases into separate entries and then process them
                #     real_tls_entries = []
                    
                #     reference_field_name = "tls_tls_record_length"

                #     if isinstance(entry[reference_field_name], (list, tuple)):

                #         # we use tls_tls_record_length because that seems one of the fields that consistently has this problem
                #         # previously we used tls_tls_record_content_type, but that's less stable apparently
                #         real_tls_entries = [{} for x in range(len(entry[reference_field_name]))] # prepare N new entry dicts where N is the amount of values for this key

                #         # print( len(entry["tls_tls_record_content_type"]) )
                #         # print( real_tls_entries )

                #         # print("/////////////////////////")
                #         # print( entry )
                #         # print("/////////////////////////")

                #         for key in entry: 

                #             # for some fields, wireshark is inconsistent
                #             # for example, when one TCP packet contains TLS server hello, change cipher spec, server handshake data
                #             # some fields are split out across the three, while others are just reflected by a single value
                #             # this is for example true for the details of the extensions in the Server Hello, but also ws.expert info for the change cipher spec for example
                #             # it doesn't seem possible to properly demux these from the wireshark JSON/XML output, as they are all just logged at the top level instead of nested
                #             # (strangely though in wireshark itself it properly assigns fields to correct records... must be problems with textual output, but nothing we can do about that)
                #             # Making matters worse, sometimes the exceptions aren't just flat values, but arrays themselves... 
                #             # (e.g., x509if_x509if_RDNSequence_item_raw (a list of many bytestrings in a given certificate) is just logged as top level item, because logic...)
                #             # we would have to create manual lists of what to demux manually to do this properly
                #             # for now, just split things out if possible. If not, just default to assigning to the first item

                #             # round 2: we discover that sometimes you can have one value for tls_tls_record_content_type (e.g., 22) but sub-values for tls_handshake_type
                #             # in other words: there records are not split out at the top level but -are- split at the handshake level... urgh
                #             # general wireshark logic somewhat seems to be: if value is the same, just use existing dictionary entry. The moment you detect something new, start making arrays.

                #             if isinstance(entry[key], (list, tuple)):
                #                 # it's a list, assign values to each real_tls_entry
                #                     # key: [val0, val1] becomes
                #                     # [0][key]: val0
                #                     # [1][key]: val1
                #                 for idx, val in enumerate(entry[key]):
                #                     # check for too large. For some reason, some arrays contain less values, but should never be -more-
                #                     if len(entry[key]) != len(entry[reference_field_name]):
                #                         # print("ConnectionStats:HandshakeTracker : Inconsitent arrays in TLS dissection... {} : {}".format(key, entry))
                #                         # exit()
                #                         real_tls_entries[0][key] = entry[key]
                #                     else:
                #                         real_tls_entries[idx][key] = val
                #             else:
                #                 # it's a single value: assign to the first real_tls_entry
                #                 real_tls_entries[0][key] = entry[key]

                #         # print("--------------------------------------------------")
                #         # print( real_tls_entries )
                #         # print("--------------------------------------------------")

                #         # for record_type in entry["tls_tls_record_content_type"]:
                #         #     if int(record_type) != TLSRecordType.APPLICATION_DATA.value:
                #         #         print("ConnectionStats:HandshakeTracker : Multiple non-Appdata record types, unexpected! {} in {} : {}".format(record_type, entry["tls_tls_record_content_type"], entry))
                #         #         # exit()
                #     else:
                #         real_tls_entries.append(entry)
                    
                #     for entry in real_tls_entries:
                #         print(".////////////////")
                #         print( entry["tls_tls_record_content_type"] )
                #         print( entry )
                #         print(".////////////////")
                #         record_type = int(entry["tls_tls_record_content_type"])

                #         if record_type == TLSRecordType.HANDSHAKE.value:
                #             # handshake_type is sometimes missing due to the reasons outline above (only logged once instead of e.g., 2-3 times even for multiple records)
                #             if "tls_tls_handshake_type" in entry:
                #                 handshake_type = entry["tls_tls_handshake_type"]

                #                 # sometimes wireshark splits handshake records at the top level, sometimes it doesn't... go figure
                #                 # so if we have multiple here, 
                #                 real_handshake_types = []

                #                 if isinstance(handshake_type, (list, tuple)):
                #                     # print("ConnectionStats:HandshakeTracker : Multiple Handshake types, unexpected! {} : {}".format(handshake_type, entry))
                #                     # raise Exception("Record with multiple handshake types")
                #                     real_handshake_types = handshake_type
                #                 else:
                #                     real_handshake_types.append( handshake_type )

                #                 for handshake_type in real_handshake_types:
                #                     # TODO: split this out into client hello, server hello, certificate, key exchange, etc.
                #                     # also clearly show TLS version (still need to figure out how wireshark logs proper 1.3 though...)
                #                     # also check for session resumption (check with tls_tls_handshake_session_id_length > 0)
                #                     # Not all traces have this, since most use session resumption (who knew!)
                #                     # example moniotr/iot-data/uk/echoplus/volume/2019-05-04_16:24:02.22s.pcap (search for tls.handshake.certificate_length)

                #                     # TODO: figure out if there is a trace where we have client-side certificates (no idea how to even identify this though)

                #                     # TODO: check for CERTIFICATE_VERIFY or CERTIFICATE_REQUEST, which is non-default behaviour we should check out later
                                    
                #                     print( entry )

                #                     recordInfo = TLSRecordInfo()
                #                     recordInfo.time = time
                #                     recordInfo.record_type = TLSRecordType.HANDSHAKE.name
                #                     recordInfo.handshake_type = TLSHandshakeType(int(handshake_type)).name

                #                     print("-------------------")
                #                     print( entry["tls_tls_record_length"] )
                #                     # print( real_tls_entries )
                #                     print("-------------------")

                #                     recordInfo.length = int(entry["tls_tls_record_length"])

                #                     self.tlsRecords[src_ip].append( recordInfo )

                #                     print("ConnectionStats:HandshakeTracker : Handshake type found {}".format(TLSHandshakeType(int(handshake_type)).name))

                #                     if "tls_tls_handshake_extensions_alpn_len" in entry and int(entry["tls_tls_handshake_extensions_alpn_len"]) > 0:
                #                         self.ALPNs[src_ip].append( entry["tls_tls_handshake_extensions_alpn_str"] )

                #                     # TODO: check for version with tls_tls_handshake_extensions_supported_version (if present, probably TLS 1.3, else look at tls_tls_record_version)


                #             # if "tls_tls_handshake_session_id_length" in entry:
                #             #     if int(entry["tls_tls_handshake_session_id_length"]) > 0:
                #             #         print("RESUMED SESSION BABY!")

                #         elif record_type == TLSRecordType.APPLICATION_DATA.value: 

                #             # only want to log the first APP_DATA for each sender (all normal traffic is APP_DATA after all, so we'd log everything otherwise)
                #             # so check if the last one added for each sender isn't already APP_DATA
                #             if len(self.tlsRecords[src_ip]) > 0 and self.tlsRecords[src_ip][-1].record_type is not TLSRecordType.APPLICATION_DATA.value:
                #                 recordInfo = TLSRecordInfo()
                #                 recordInfo.time = time
                #                 recordInfo.record_type = TLSRecordType.APPLICATION_DATA.name
                #                 recordInfo.length = int(entry["tls_tls_record_length"])

                #                 self.tlsRecords[src_ip].append( recordInfo )

                #                 self.applicationDataCount += 1

                #         elif record_type == TLSRecordType.ALERT.value: 
                #             recordInfo = TLSRecordInfo()
                #             recordInfo.time = time
                #             recordInfo.record_type = TLSRecordType.ALERT.name
                #             recordInfo.length = int(entry["tls_tls_record_length"])

                #             self.alertRecords.append( packet )
                # else:
                #     # tls entry without record sometimes happens if e.g., we have a TCP spurious retransmit
                #     if "text" not in entry or entry["text"] != "Ignored Unknown Record":    
                #         print("ConnectionStats:HandshakeTracker : tls entry had no record type... SHOULDN'T HAPPEN? {} in {}".format(entry, packet))
                #         raise Exception("TLS record without record type")
        
        if "ssl" in packet["layers"]:
            # note: apparently SSLv2 shows up as {"tls.record.version": "0x00000002"} for some reason
            # keep this for good measure though 
            print("ConnectionStats:HandshakeTracker : SSL packet found. TODO: {}".format(packet))
            raise Exception("SSL packet found, not supprorted yet")

    def serialize(self, output):

        if len(self.tcpHandshakePackets) > 0:
            output["tcp"] = {}
            output["tcp"]["handshake_packets"] = self.tcpHandshakePackets

        if len(self.tlsRecords) == 0:
            return

        output["tls"] = {}
        output["tls"]["full_handshake"] = self.clientHelloSeen and self.applicationDataCount >= 2

        if len(self.ALPNs) > 0:
            output["tls"]["ALPN"] = self.ALPNs

        output["tls"]["versions"] = self.tlsVersion

        output["tls"]["records"] = self.tlsRecords

        output["tls"]["resumed"] = self.resumedSession

class RetransmissionTracker:
    def __init__(self):
        self.retransmissions = []

    def update(self, connection, packet):
        if "tcp" in packet["layers"]:

            # if packet["layers"]["frame"]["frame.number"] == "87":
            #     print( json.dumps(packet["layers"]["tcp"]) )
            #     raise Exception("SPURIOUS IS IN HERE")

            # data is in long path : packet["layers"]["tcp"]["tcp.analysis"]["tcp.analysis.flags"]["_ws.expert"]["tcp.analysis.spurious_retransmission"]
            if "tcp.analysis" in packet["layers"]["tcp"]:
                
                if isinstance(packet["layers"]["tcp"]["tcp.analysis"], (list, tuple)):
                    print("RetransmissionTracker: tcp.analysis was an array. UNEXPECTED!")
                    print( json.dumps(packet["layers"]["tcp"]) )
                    raise Exception("RetransmissionTracker: tcp.analysis was an array. UNEXPECTED!") 


                if "tcp.analysis.flags" in packet["layers"]["tcp"]["tcp.analysis"]:

                    if isinstance(packet["layers"]["tcp"]["tcp.analysis"]["tcp.analysis.flags"], (list, tuple)):
                        print("RetransmissionTracker: tcp.analysis.flags was an array. UNEXPECTED!")
                        print( json.dumps(packet["layers"]["tcp"]) )
                        raise Exception("RetransmissionTracker: tcp.analysis.flags was an array. UNEXPECTED!") 

                    if "_ws.expert" in packet["layers"]["tcp"]["tcp.analysis"]["tcp.analysis.flags"]:
                        # can be a single entry or an array. To make easier to process, put the single entry in an array
                        expert_entries = []
                        if not isinstance(packet["layers"]["tcp"]["tcp.analysis"]["tcp.analysis.flags"]["_ws.expert"], (list, tuple)):
                            expert_entries = [ packet["layers"]["tcp"]["tcp.analysis"]["tcp.analysis.flags"]["_ws.expert"] ]
                        else:
                            expert_entries = packet["layers"]["tcp"]["tcp.analysis"]["tcp.analysis.flags"]["_ws.expert"]

                        for entry in expert_entries:
                            if "tcp.analysis.spurious_retransmission" in entry:
                                self.retransmissions.append( "spurious" )
                                break # wireshark lists both spurious and normal retransmission in the _ws_expert array, but we only want one of them of course
                            elif "tcp.analysis.fast_retransmission" in entry:
                                self.retransmissions.append( "fast" )
                                break
                            elif "tcp.analysis.retransmission" in entry:
                                self.retransmissions.append( "normal" )
                                break

    def serialize(self, output):
        # if len(self.retransmissions) > 0:
        #     print( "RETRANSMISSIONS FOUND {}".format(len(self.retransmissions)) )
        # TODO: we could expose the real types and maybe timings, seq nrs and sizes eventually, but for now this is probably ok
        output["retransmission_count"] = len(self.retransmissions)

class PacketCounter:
    def __init__(self):
        self.totalPacketCount = 0
        self.totalByteCount = 0
        self.packetCounts = {}
        self.byteCounts = {}
    
    def update(self, connection, packet):
        self.totalPacketCount += 1
        self.totalByteCount += int( packet["layers"]["frame"]["frame.len"] )

        src_ip = packet["layers"]["ip"]['ip.src']
        if src_ip not in self.packetCounts:
            self.packetCounts[src_ip] = 0
            self.byteCounts[src_ip] = 0

        self.packetCounts[src_ip] += 1
        self.byteCounts[src_ip] += int( packet["layers"]["frame"]["frame.len"] )

    def serialize(self, output):
        output["total_packet_count"] = self.totalPacketCount
        output["total_byte_count"] = self.totalByteCount
        output["byte_counts"] = self.byteCounts
        output["packet_counts"] = self.packetCounts

# class LongestIdlePeriodCounter:
#     def __init__(self):
#         self.longestIdlePeriod = -1
    
#     def update(self, connection, packet):
#         print("ConnectionEstablishedTracker:LongestIdlePeriodCounter : NOT IMPLEMENTED")

#         # TODO: wireshark analyses TCP and indicates if a packet is a Keep-Alive one in the expert info 

#     def serialize(self, output):
#         output["longest_idle"] = self.packetCount

# TODO: potentially add a rolling RTT calculator (correlate TCP seq nrs with acks) -> will be noisy though, make sure we need it first 

class ConnectionEstablishedTracker:
    def __init__(self):
        self.initialPacket = None
        self.packet1 = None # not the same as initialPacket. Packet1 is e.g., the SYN of a TCP connection. If there is no SYN, initialPacket is set, but packet1 is not
        self.packet2 = None

        self.TCPstreamNr = None

        self.initial_rtt = -1

    def update(self, connection, packet):

        if self.initialPacket is None:
            if "ip" in packet["layers"]:
                self.initialPacket = packet

        # for TCP, wireshark calculates the initial_RTT based on the three-way handshake 
        # (see https://blog.packet-foo.com/2014/07/determining-tcp-initial-round-trip-time/)
        if "tcp" in packet["layers"]:

            if self.TCPstreamNr is not None and self.TCPstreamNr != packet["layers"]["tcp"]["tcp.stream"]:
                print("ConnectionEstablishedTracker: TCPStreamNr not the same for this connection, SHOULDN'T HAPPEN! {} -> {}".format(self.TCPstreamNr, packet["layers"]["tcp"]["tcp.stream"]))
                raise Exception("ConnectionEstablishedTracker: TCPStreamNr not the same for this connection, SHOULDN'T HAPPEN!")

            self.TCPstreamNr = packet["layers"]["tcp"]["tcp.stream"]
            

            if "tcp.analysis.initial_rtt" in packet["layers"]["tcp"]:
                print("DEBUGGING: TCP ANALYSIS correctly FOUND! remove this!")
                exit()
                new_initial_rtt = float(packet["layers"]["tcp"]["tcp.analysis.initial_rtt"])
                if self.initial_rtt > 0 and self.initial_rtt != new_initial_rtt:
                    print("ConnectionEstablishedTracker: different value for initial RTT found during connection {} -> {}".format(self.initial_rtt, packet["layers"]["tcp"]["tcp.analysis.initial_rtt"]))

                self.initial_rtt = new_initial_rtt

        if self.packet1 is not None and self.packet2 is not None:
            return

        if "tcp" in packet["layers"]:
            # TCP has a clear connection setup with SYN, SYN/ACK, ACK
            # if we see the first two, we know we've observed the start of the connection
            if "tcp.flags.syn_raw" in packet["layers"]["tcp"]:
                if packet["layers"]["tcp"]["tcp.flags.syn_raw"] == "1" and packet["layers"]["tcp"]["tcp.flags.ack_raw"] != "1":
                    self.packet1 = packet
                elif packet["layers"]["tcp"]["tcp.flags.syn_raw"] == "1" and packet["layers"]["tcp"]["tcp.flags.ack_raw"] == "1": 
                    self.packet2 = packet

        
        # TODO: in UDP, also take into account incoming "connections" when estimating RTT 
        if "udp" in packet["layers"]:
            # UDP doesn't have a clear connection setup, we just use the first two packets in different directions we see
            if self.packet1 is None:
                self.packet1 = packet
                self.sendtime = float(packet["layers"]["frame"]["frame.time_epoch"])
            elif self.packet2 is None and packet["layers"]["ip"]['ip.src'] == self.packet1["layers"]["ip"]['ip.dst']:
                self.packet2 = packet
                self.receivetime = float(packet["layers"]["frame"]["frame.time_epoch"])
                self.initial_rtt = self.receivetime - self.sendtime

            # elif self.packet2 is None:
            #     print("////////////////////")
            #     print("////////// DEBUG: Two UDP packets from the same direction seen {} -> {}".format(self.packet1["layers"]["ip"]['ip.src'], packet["layers"]["ip"]['ip.src']))
            #     print("////////////////////")
            #     exit()

        if "quic" in packet["layers"]:
            print("ConnectionEstablishedTracker:update : QUIC connection tracking not yet implemented")

    def serialize(self, output):
        if self.packet1 is not None and self.packet2 is not None:
            output["connection_established"] = True
            if self.initial_rtt > 0:
                output["initial_RTT"] = self.initial_rtt * 1000 # it is in seconds, we want it in milliseconds
                # print("DEBUG: initial_rtt {}".format(self.initial_rtt * 1000))
        else:
            output["connection_established"] = False

        if self.initialPacket is not None:
            output["first_packet_from"] = self.initialPacket["layers"]["ip"]['ip.src']

        if self.TCPstreamNr is not None:
            output["tcp_stream_nr"] = self.TCPstreamNr

class ActivityTracker:
    def __init__(self):
        self.threshold = 1 # in seconds
        self.timestamps = {}
        self.datasizes = {}
        self.packetcounts = {}

        self.tcpstreamDEBUG = -1

        self.dataAccumulator = {} # for convenience so we're not constantly updating the last entry in the .datasizes lists
        self.countAccumulator = {} # for convenience so we're not constantly updating the last entry in the .packetcounts lists
        self.lastTimestamp = {} # for convenience so we're not constantly updating the last entry in the .timestamps lists

    def update(self, connection, packet):
        if "tcp" not in packet["layers"]:
            return

        self.tcpstreamDEBUG = packet["layers"]["tcp"]["tcp.stream"]

        time = float(packet["layers"]["frame"]["frame.time_epoch"])
        size = int(packet["layers"]["tcp"]["tcp.len"]) + int( packet["layers"]["tcp"]["tcp.hdr_len"] ) # we explicitly include header length because this is in the QUIC payload

        src_ip = packet["layers"]["ip"]['ip.src']
        if src_ip not in self.timestamps:
            # first packet
            self.timestamps[src_ip] = [ time ]
            self.datasizes[src_ip] = []
            self.packetcounts[src_ip] = []

            self.dataAccumulator[src_ip] = size
            self.lastTimestamp[src_ip] = time
            self.countAccumulator[src_ip] = 1

        else:
            # goal here is not to store all timestamps, but find intervals
            # e.g., say the main bulk is sent in the first 2s, but then we have 30s of keepalives every x seconds
            # this is reflected in both the timestamps and the accumulated data per interval

            if ( time - self.lastTimestamp[src_ip] > self.threshold ): # more than 1 second difference between packets

                # print( "NEW INTERVAL FOUND {} -> {}".format(self.lastTimestamp[src_ip], time))

                self.timestamps[src_ip].append( self.lastTimestamp[src_ip] ) # close previous interval
                self.timestamps[src_ip].append( time ) # open next interval
                # if consistent keepalives, the intervals' start and end times will be the same

                self.datasizes[src_ip].append( self.dataAccumulator[src_ip] )
                self.dataAccumulator[src_ip] = size # current packet counts for the next interval

                self.packetcounts[src_ip].append( self.countAccumulator[src_ip] )
                self.countAccumulator[src_ip] = 1 # current packet counts for the next interval
            else:
                self.dataAccumulator[src_ip] += size
                self.countAccumulator[src_ip] += 1
            
            self.lastTimestamp[src_ip] = time

    def serialize(self, output):
        if len(self.timestamps) > 0:
            for ip in self.timestamps:

                # make sure we always have the timestamps/size of the final interval in there
                # if self.timestamps[ip][-1] != self.lastTimestamp[ip]:
                self.timestamps[ip].append(self.lastTimestamp[ip])
                self.datasizes[ip].append(self.dataAccumulator[ip])
                self.packetcounts[ip].append(self.countAccumulator[ip])

            for ip in self.timestamps:
                # DEBUG: REMOVE: 
                # if len(self.timestamps[ip]) > 8:
                #     print( json.dumps(self.timestamps) )
                #     # print( json.dumps(self.lastTimestamp) )
                #     print( json.dumps(self.datasizes) )
                #     # print( json.dumps(self.dataAccumulator) )
                #     print( self.tcpstreamDEBUG )
                #     raise Exception("TODO:REMOVE: TimeStampTracker:serialize : connection with large intervals found!")

                # for i in range(1, len(self.datasizes[ip]) ):
                #     if ( self.datasizes[ip][i] > 1000 ): # first interval is typically large, but looking for big intermediates here 
                #         print( json.dumps(self.timestamps) )
                #         # print( json.dumps(self.lastTimestamp) )
                #         print( json.dumps(self.datasizes) )
                #         # print( json.dumps(self.dataAccumulator) )
                #         print( json.dumps(self.packetcounts) )
                #         print( self.tcpstreamDEBUG )
                #         raise Exception("TODO:REMOVE: TimeStampTracker:serialize : BIG intermediate interval found!")

                # sanity check
                if len(self.datasizes[ip]) > 0 and ( len(self.timestamps[ip]) % 2 != 0 or len(self.datasizes[ip]) != len(self.timestamps[ip]) / 2): # if there was just a single packet, it's normal that there's just a single entry
                    print( "TODO:REMOVE: TimeStampTracker:serialize: non-even amount of timestamps recorded... should not happen!" )
                    print( self.timestamps )
                    print( self.datasizes )
                    raise Exception("TODO:REMOVE: TimeStampTracker:serialize : connection with large intervals found!")



            output["activity"] = {}
            output["activity"]["threshold"] = self.threshold
            output["activity"]["intervals"] = self.timestamps
            output["activity"]["datasizes"] = self.datasizes
            output["activity"]["packetcounts"] = self.packetcounts


class RTTTracker:
    def __init__(self):
        self.RTTs = {}

    def update(self, connection, packet):
        if "tcp" in packet["layers"]:

            # ideally, we have observed the start of a TCP connection and have a good estimate of initial_rtt from wireshark
            # however, sometimes we have not + the RTT can evolve during a connection
            # luckily, wireshark also tracks ACK latencies for us, though they are more difficult to map to actual RTT depending on observer location
            # (for more info, see https://blog.packet-foo.com/2014/07/determining-tcp-initial-round-trip-time/)
            # still, as for our work, most datasets are captured close to the client, we can use these ack latencies as a kind of lower bound to the RTT
            
            # NOTE: the ack latencies will typically be bi-modal: if we're capturing close to the client, the incoming packet from the server and the corresponding ACK from the client fill follow each other quickly
            # on the other hand, a packet sent by the client will be separated from the server's ACK by a longer time period
            # As such, we should discard the lower mode and only keep the higher, as it more correctly approaches the RTT
            # this is made more difficult by the fact that the client will typically be ACKing more than the server, as it typically downloads more than it uploads
            # we tried this first, taking 40 measurements and then calculateing the modes using a 1D kmeans clustering algorithm and cutoff the measurements below the center of the two modes
            # however, this was quite vulnerable to outliers.
            # The eventual solution we settled on was to simply group acks by sender and do post-hoc analysis on that
            # this is because in a lot of the traces we saw, one side (strangely, the acks sent by the remote endpoint) were much more stable and closer to the handshake RTT than those from the other side
            # Note that Wireshark does not calculate analysis.ack_rtt for -all- TCP acks for some reason. So it's still a bit fishy

            if "tcp.analysis.ack_rtt" in packet["layers"]["tcp"]:

                src_ip = packet["layers"]["ip"]['ip.src']
                if src_ip not in self.RTTs:
                    self.RTTs[src_ip] = []

                rtt = int( round(float(packet["layers"]["tcp"]["tcp.analysis.ack_rtt"]) * 1000)) # is logged in seconds, we want milliseconds
                self.RTTs[src_ip].append( rtt )

    def serialize(self, output):
        if len(self.RTTs) > 0:
            output["ack_latencies"] = self.RTTs
            medians = {}
            for ip in self.RTTs:
                medians[ ip ] = statistics.median( self.RTTs[ ip ] )
            output["median_ack_latencies"] = medians
            # # print( "Median latency : {}, spotcheck: {}".format(output["median_ack_latency"], self.RTTs[:20] ) )
            # print( self.RTTs )
            # print( "{} -> {}".format( output["initial_RTT"] if "initial_RTT" in output else "?", output["median_ack_latencies"] ) )

class ConnectionCloseType(Enum):
    NONE = 1,
    GRACEFUL = 2,   # e.g., TCP FIN
    FORCED = 3,     # e.g., TCP RST 
    IMPLICIT = 4,   # e.g., DNS response received to a query

class ConnectionClosedTracker:
    def __init__(self):
        self.closed = ConnectionCloseType.NONE

    def update(self, connection, packet):
        
        # we can only really track this for TCP connections which have a clear end
        # though we can use heuristics for some others (e.g., DNS request/response) TODO
        if "tcp" in packet["layers"]:
            if packet["layers"]["tcp"].get("tcp.flags.reset", False):
                self.closed = ConnectionCloseType.FORCED
            elif packet["layers"]["tcp"].get("tcp.flags.fin", False): 
                self.closed = ConnectionCloseType.GRACEFUL

        # if self.closed is not ConnectionCloseType.NONE:
        #     print("Connection close found")
        #     print( packet )
        #     exit()

    def serialize(self, output):
        output["connection_closed"] = self.closed is not ConnectionCloseType.NONE
        if output["connection_closed"]:
            output["connection_close_type"] = self.closed.name