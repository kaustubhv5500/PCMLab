"""Custom topology example

Two directly connected switches plus a host for each switch:

host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        leftHost = self.addHost('h1')
        rightHost = self.addHost('h2')
        leftSwitch = self.addSwitch('s3')
        rightSwitch = self.addSwitch('s4')

        # TODO 7 add links
        self.addLink(leftHost, leftSwitch) # leftHost (h1) <--> leftSwitch (s3)
        self.addLink(leftSwitch, rightSwitch) # leftSwitch (s3) <--> rightSwitch (s4)
        self.addLink(rightSwitch, rightHost) # rightSwitch (s4) <--> rightHost (h2)


topos = { 'mytopo': ( lambda: MyTopo() ) }
