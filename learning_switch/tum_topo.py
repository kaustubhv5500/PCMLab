"""
Simplified TUM network topology.
"""
from mininet.topo import Topo

class MyTopo( Topo ):
    "Simplified TUM network topology."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # TODO 1. Complete the topology according to the tutorial figure
        # Add hosts and switches
        m_p1 = self.addHost(XXX)               # m p1
        m_p2 = self.addHost(XXX)               # m p2
        m_s1 = self.addHost(XXX)               # m s1
        m_s2 = self.addHost(XXX)               # m s2

        g_p1 = self.addHost(XXX)               # g p1
        g_p2 = self.addHost(XXX)               # g p2
        g_s1 = self.addHost(XXX)               # g s1
        g_s2 = self.addHost(XXX)               # g s2

        munich = self.addSwitch(XXX)           # s1

        munich_prof = self.addSwitch(XXX)      # s2
        munich_stud = self.addSwitch(XXX)      # s3

        garching = self.addSwitch(XXX)         # s4
        garching_prof = self.addSwitch(XXX)    # s5
        garching_stud = self.addSwitch(XXX)    # s6

        #backbone link
        self.addLink(XXX)                      # munich <--> garching
        #links between switches in garching
        self.addLink(XXX)                      # garching <--> garching prof
        self.addLink(XXX)                      # garching <--> garching stud
        #links between switches in munich
        self.addLink(XXX)                      # munich <--> munich prof
        self.addLink(XXX)                      # munich <--> munich stud

        #links between hosts and switches
        self.addLink(XXX)                      # m p1 <--> munich prof
        self.addLink(XXX)                      # m p2 <--> munich prof
        self.addLink(XXX)                      # m s1 <--> munich stud
        self.addLink(XXX)                      # m s2 <--> munich stud
        self.addLink(XXX)                      # g p1 <--> garching prof
        self.addLink(XXX)                      # g p2 <--> garching prof
        self.addLink(XXX)                      # g s1 <--> garching stud
        self.addLink(XXX)                      # g s2 <--> garching stud

topos = { 'mytopo': ( lambda: MyTopo() ) }
