from enum import Enum

from lib.models.Connection import ConnectionPhase

class ConnectionCounter:
    def __init__(self):
        self.connectionsPerPhase = {}
        self.connectionsPerPhase[ ConnectionPhase.UNKNOWN.name ] = []
        self.connectionsPerPhase[ ConnectionPhase.INITIAL.name ] = []
        self.connectionsPerPhase[ ConnectionPhase.IDLE.name ] = []
        self.connectionsPerPhase[ ConnectionPhase.INTERACTION.name ] = []
    
    def update(self, traces, connections):
        for trace in traces:
            self.connectionsPerPhase[ trace.phase.name ].append( len(trace.connections) )


    def serialize(self, output):
        output["connection_counts"] = self.connectionsPerPhase

class RTTTracker:
    def __init__(self):
        self.rttPerPhase = {}
        self.rttPerPhase[ ConnectionPhase.UNKNOWN.name ] = []
        self.rttPerPhase[ ConnectionPhase.INITIAL.name ] = []
        self.rttPerPhase[ ConnectionPhase.IDLE.name ] = []
        self.rttPerPhase[ ConnectionPhase.INTERACTION.name ] = []
    
    def update(self, traces, connections):

        for connection in connections:
            if connection.estimated_RTT:
                self.rttPerPhase[ connection.phase.name ].append( connection.estimated_RTT )
                # if connection.estimated_RTT < 10:
                #     self.rttPerPhase[ connection.phase.name ].append( connection.info )


    def serialize(self, output):
        output["rtts"] = self.rttPerPhase
