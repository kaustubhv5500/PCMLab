#!/usr/bin/env python3

import os, json, argparse
from time import sleep

from p4_mininet import P4Host

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI

from p4runtime_switch import P4RuntimeSwitch


class ExerciseTopo(Topo):

    def __init__(self, hosts, switches, links, log_dir, bmv2_exe, pcap_dir, switch_json, **opts):
        Topo.__init__(self, **opts)
        host_links = []
        switch_links = []

        # assumes host always comes second for host<-->switch links
        for link in links:
            if link['node2'][0] == 'm' or link['node2'][0] == 'g':
                host_links.append(link)
            else:
                switch_links.append(link)

        for sw, params in switches.items():
            self.addSwitch(sw,
                           sw_path=bmv2_exe,
                           json_path=switch_json,
                           grpc_port=params['grpc_port'],
                           thrift_port=params['thrift_port'],
                           log_console=True,
                           device_id=params['device_id'],
                           pcap_dump=pcap_dir,
                           cpu_port=255,
                           log_file="%s/%s.log" % (log_dir, sw))

        for link in host_links:
            sw_name, sw_port = self.parse_name_port(link['node1'])
            host_name, host_port = self.parse_name_port(link['node2'])
            host_ip = hosts[host_name]['ip']
            host_mac = hosts[host_name]['mac']
            self.addHost(host_name, ip=host_ip, mac=host_mac)
            self.addLink(sw_name, host_name, port1=sw_port, port2=host_port, delay='0ms', bw=1000)

        for link in switch_links:
            sw1_name, sw1_port = self.parse_name_port(link['node1'])
            sw2_name, sw2_port = self.parse_name_port(link['node2'])
            self.addLink(sw1_name, sw2_name, port1=sw1_port, port2=sw2_port, delay='0ms', bw=1000)

    def parse_name_port(self, node):
        assert(len(node.split('-')) == 2)
        sw_name, sw_port = node.split('-')
        try:
            # ethX
            sw_port = int(sw_port[3:])
        except Exception as e:
            print("Exception %s" % e)
            raise Exception('Invalid switch node in topology file: {}'.format(node))
        return sw_name, sw_port


class ExerciseRunner:

    def logger(self, *items):
        if not self.quiet:
            print(' '.join(items))

    def __init__(self, topo_file, log_dir, pcap_dir, switch_json, bmv2_exe='simple_switch', quiet=False):
        self.quiet = quiet
        self.logger('Reading topology file.')
        with open(topo_file, 'r') as f:
            topo = json.load(f)
        self.hosts = topo['hosts']
        self.switches = topo['switches']
        self.links = topo['links']

        # Ensure all the needed directories exist and are directories
        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception("'%s' exists and is not a directory!" % dir_name)
                os.mkdir(dir_name)
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.switch_json = switch_json
        self.bmv2_exe = bmv2_exe
        self.topo = None
        self.net = None
        self.controller = None

    def run_exercise(self):
        # Initialize mininet with the topology specified by the config
        self.create_network()
        self.net.start()
        sleep(1)

        # Setting up hosts
        self.program_hosts()
        sleep(1)

        self.do_net_cli()
        # stop right after the CLI is exited
        self.net.stop()

    def create_network(self):
        self.logger("Building mininet topology.")
        self.topo = ExerciseTopo(self.hosts, self.switches, self.links, self.log_dir, self.bmv2_exe, self.pcap_dir, self.switch_json)
        self.net = Mininet(topo=self.topo,
                           link=TCLink,
                           host=P4Host,
                           switch=P4RuntimeSwitch,
                           controller=None)

    def program_hosts(self):
        for host_name, host_info in list(self.hosts.items()):
            h = self.net.get(host_name)
            if "commands" in host_info:
                for cmd in host_info["commands"]:
                    h.cmd(cmd)

    def do_net_cli(self):
        for s in self.net.switches:
            s.describe()
        for h in self.net.hosts:
            h.describe()
        self.logger("Starting mininet CLI")
        print('')
        print('======================================================================')
        print('Welcome to the BMV2 Mininet CLI!')
        print('======================================================================')
        print('')
        CLI(self.net)


def get_args():
    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')
    default_pcaps = os.path.join(cwd, 'pcaps')
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--quiet', help='Suppress log messages.',
                        action='store_true', required=False, default=False)
    parser.add_argument('-t', '--topo', help='Path to topology json',
                        type=str, required=False, default='./topology.json')
    parser.add_argument('-l', '--log-dir', type=str, required=False, default=default_logs)
    parser.add_argument('-p', '--pcap-dir', type=str, required=False, default=default_pcaps)
    parser.add_argument('-j', '--switch_json', type=str, required=False)
    parser.add_argument('-b', '--behavioral-exe', help='Path to behavioral executable',
                        type=str, required=False, default='simple_switch_grpc')
    return parser.parse_args()


if __name__ == '__main__':
    from mininet.log import setLogLevel
    setLogLevel("info")
    args = get_args()
    exercise = ExerciseRunner(args.topo, args.log_dir, args.pcap_dir, args.switch_json, args.behavioral_exe, args.quiet)
    exercise.run_exercise()

