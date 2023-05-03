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
        m_p1 = self.addHost('m_p1')               # m p1
        m_p2 = self.addHost('m_p2')               # m p2
        m_s1 = self.addHost('m_s1')               # m s1
        m_s2 = self.addHost('m_s2')               # m s2

        g_p1 = self.addHost('g_p1')               # g p1
        g_p2 = self.addHost('g_p2')               # g p2
        g_s1 = self.addHost('g_s1')               # g s1
        g_s2 = self.addHost('g_s2')               # g s2

        munich = self.addSwitch('s1')           # s1
        munich_prof = self.addSwitch('s2')      # s2
        munich_stud = self.addSwitch('s3')      # s3

        garching = self.addSwitch('s4')         # s4
        garching_prof = self.addSwitch('s5')    # s5
        garching_stud = self.addSwitch('s6')    # s6

        # Backbone link
        self.addLink(munich, garching)                             # munich <--> garching
        # Links between switches in garching
        self.addLink(garching, garching_prof)                  # garching <--> garching prof
        self.addLink(garching, garching_stud)                  # garching <--> garching stud
        # Links between switches in munich
        self.addLink(munich, munich_prof)                      # munich <--> munich prof
        self.addLink(munich, munich_stud)                      # munich <--> munich stud

        # Links between hosts and switches
        self.addLink(m_p1, munich_prof)                      # m p1 <--> munich prof
        self.addLink(m_p2, munich_prof)                      # m p2 <--> munich prof
        self.addLink(m_s1, munich_stud)                      # m s1 <--> munich stud
        self.addLink(m_s2, munich_stud)                      # m s2 <--> munich stud
        self.addLink(g_p1, garching_prof)                    # g p1 <--> garching prof
        self.addLink(g_p2, garching_prof)                    # g p2 <--> garching prof
        self.addLink(g_s1, garching_stud)                    # g s1 <--> garching stud
        self.addLink(g_s2, garching_stud)                    # g s2 <--> garching stud

topos = { 'mytopo': ( lambda: MyTopo() ) }
