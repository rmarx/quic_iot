from enum import Enum

# class VantagePoint(Enum):
#     CLIENT = 1,
#     SERVER = 2,
#     UNKNOWN = 3

# a connection is loosely identified as data flowing in a 5-tuple
# this encompasses TCP connections, but also e.g., DNS request-answer exchanges
# we use a 5-tuple because e.g., with QUIC, you can have both TCP and UDP connections to 443 (or DNS to 53)

# we also keep track of the MAC addresses because some device lists couple device names to macs instead of fixed IPs

class ConnectionPhase(Enum):
    UNKNOWN = 0,
    INITIAL = 1, # device power up
    IDLE = 2, # device idle
    INTERACTION = 3 # during device interaction

class Connection:
    def __init__(self, ip1, port1, ip2, port2, transport_protocol):
        self.ip1 = ip1
        self.port1 = port1
        self.ip2 = ip2
        self.port2 = port2
        self.protocol = transport_protocol
        self.mac1 = None
        self.mac2 = None

        self.interpreters = []

    def set_macs(self, mac1, mac2):
        if self.mac1 is not None:
            if self.mac1 is not mac1 and self.mac2 is not mac2:
                raise Exception("Connection:set_macs : more than 2 macs detected in a connection... should be impossible {} {} => {} {} ".format(self.mac1, self.mac2, mac1, mac2)) 

        self.mac1 = mac1
        self.mac2 = mac2

    def equals(self, ip1, port1, ip2, port2, transport_protocol):
        # print("Comparing " + "[{}] {}:{} -> {}:{}".format(transport_protocol, ip1, port1, ip2, port2) + " to " + str(self) )
        
        # data flowing in two directions is the same logical connection
        if transport_protocol == self.protocol:
            if ( ip1 == self.ip1 and ip2 == self.ip2 ) or ( ip1 == self.ip2 and ip2 == self.ip1 ):
                if ( port1 == self.port1 and port2 == self.port2 ) or ( port1 == self.port2 and port2 == self.port1 ):
                    return True 
        
        return False

    def get_interpreters(self):
        return self.interpreters

    def serialize(self, output):
        output["info"] = {
            "transport_protocol": self.protocol.name,
            "endpoint1": {
                "ip": self.ip1,
                "port": self.port1,
                "mac": self.mac1
            },
            "endpoint2": {
                "ip": self.ip2,
                "port": self.port2,
                "mac": self.mac2
            }
        }

    @staticmethod
    def deserialize(input):
        output = Connection( input["endpoint1"]["ip"], input["endpoint1"]["port"], input["endpoint2"]["ip"], input["endpoint2"]["port"], input["transport_protocol"] )
        output.set_macs( input["endpoint1"]["mac"], input["endpoint2"]["mac"] )
        return output

    def __str__(self):
        return "[{}] {}:{} -> {}:{}".format(self.protocol.name, self.ip1, self.port1, self.ip2, self.port2)
