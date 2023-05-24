from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from p4_mininet import P4Host, P4Switch
from p4runtime_switch import P4RuntimeSwitch

class OneSwitchTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        # TODO 2. Creating the topology
        switch = self.addSwitch('S1',
                                sw_path = 'simple_switch_grpc',
                                json_path = 'build/switch_pipeline.json',
                                thrift_port = 9090,
                                pcap_dump = 'pcaps')

        host_1 = self.addHost('H1',
                                ip = "10.0.0.1/24",
                                mac = 'c7:e8:02:aa:a0:01')
        self.addLink(host_1, switch)

        host_2 = self.addHost('H2',
                                ip = "10.0.0.2/24",
                                mac = 'c7:e8:02:aa:a0:02')
        self.addLink(host_2, switch)


def main():
    topo = OneSwitchTopo()
    net = Mininet(topo=topo, host=P4Host, switch=P4RuntimeSwitch, controller=None)
    net.start()
    CLI(net)
    net.stop()

if __name__ == "__main__":
    main()
