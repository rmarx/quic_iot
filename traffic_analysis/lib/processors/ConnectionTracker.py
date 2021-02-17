from lib.models.Connection import Connection
from enum import Enum

class TransportProtocol(Enum):
    TCP = 1,
    UDP = 2,
    QUIC = 3

class ApplicationProtocol(Enum):
    HTTP = 1,
    HTTPS = 2,
    DNS = 3,
    DHCP = 4

class SecurityProtocol(Enum):
    TLS = 1

class ConnectionTracker:

    def __init__(self):
        self.connections = []

    def find_connection(self, packet):
        
        # assume for now that devices don't change IP during a single trace
        ip1 = None
        ip2 = None
        port1 = None 
        port2 = None 
        transport_protocol = None

        if "layers" not in packet:
            return None

        if "ip" in packet["layers"]:
            ip1 = packet["layers"]["ip"]['ip.src']
            ip2 = packet["layers"]["ip"]['ip.dst']

        if "tcp" in packet["layers"]:
            transport_protocol = TransportProtocol.TCP
            port1 = packet["layers"]["tcp"]['tcp.srcport']
            port2 = packet["layers"]["tcp"]['tcp.dstport']
        
        if "udp" in packet["layers"]:
            transport_protocol = TransportProtocol.UDP
            port1 = packet["layers"]["udp"]['udp.srcport']
            port2 = packet["layers"]["udp"]['udp.dstport']

        if "quic" in packet["layers"]:
            transport_protocol = TransportProtocol.QUIC

        if ip1 is None or port1 is None: # unsupported protocols in this packet, no IP or transport protocol found (e.g., LLC protocol)
            return None

        # TODO: eventually maybe optimize this to a hash table? 
        # Though we don't expect the amount of connections to be very high per trace and this should be fast enough
        for connection in self.connections:
            if connection.equals(ip1, port1, ip2, port2, transport_protocol):
                return connection


        application_protocol = None 
        security_protocol = None
        mac1 = None
        mac2 = None
        
        if "eth" in packet["layers"]:
            mac1 = packet["layers"]["eth"]['eth.src']
            mac2 = packet["layers"]["eth"]['eth.dst']
        
        connection = Connection(ip1, port1, ip2, port2, transport_protocol)
        connection.set_macs(mac1, mac2)
        self.connections.append( connection )

        return connection

    def get_connections(self):
        return self.connections

    # def serialize(self):
    #     infoList = []

    #     for connection in self.connections:
    #         connectionInfo = {}
    #         connection.serialize(connectionInfo)

    #         for interpreter in connection.get_interpreters():
    #             interpreter.serialize(connectionInfo)

    #         infoList.append(connectionInfo)

    #     return { "connections": infoList }


