import json
import os
import sys

from . import bmv2
from . import helper
from threading import Thread

from scapy.all import Ether, IP, ARP
from p4.v1.p4runtime_pb2 import PacketOut
import networkx as nx


class ConfException(Exception):
    pass


class P4RuntimeController:

    def __init__(self, switches, hosts, links, quiet, log_dir):
        self.switches = switches
        self.hosts = hosts
        self.links = links
        self.quiet = quiet
        self.log_dir = log_dir

        self.topology = nx.Graph()
        self.init_topology()

    def init_topology(self):
        for host_name, host_params in self.hosts.items():
            self.topology.add_node(host_name, ip=host_params['ip'].split('/')[0], mac=host_params['mac'])
        for switch_name, switch_params in self.switches.items():
            self.topology.add_node(switch_name,
                                   ip=switch_params['ip'],
                                   mac='',
                                   runtime_json=switch_params['runtime_json'],
                                   grpc_port=switch_params['grpc_port'],
                                   thrift_port=switch_params['thrift_port'],
                                   device_id=switch_params['device_id'])
        for link in self.links:
            node1, node1_port = self.get_node_port(link['node1'])
            node2, node2_port = self.get_node_port(link['node2'])
            self.topology.add_edge(node1, node2, anchors={node1: node1_port, node2: node2_port})

    def get_node_port(self, node):
        if '-' in node:
            node_port = node.split('-')
            return node_port[0], node_port[1]
        else:
            return node, 'p1'

    def logger(self, *items):
        if not self.quiet:
            print(' '.join(items))

    def print_topology(self):
        # TODO 12. Checking the topology at the controller side
        self.logger(f"Host List: ")
        for host in self.hosts.keys():
            self.logger(host, "IP: ", self.hosts[host]['ip'], "MAC: ", self.hosts[host]['mac'])

        self.logger(f"Links: ")
        for link in self.links:
            self.logger(link['node1'], '-->', link['node2'])

    def program_switch_p4runtime(self, sw_name, sw_dict):
        grpc_port = sw_dict['grpc_port']
        device_id = sw_dict['device_id']
        runtime_json = sw_dict['runtime_json']
        ip = sw_dict['ip']
        self.logger('Configuring switch %s using P4Runtime with file %s' % (sw_name, runtime_json))
        self.logger('grpc_port %s and device_id %s' % (grpc_port, device_id))
        with open(runtime_json, 'r') as sw_conf_file:
            outfile = '%s/%s-p4runtime-requests.txt' % (self.log_dir, sw_name)
            self.program_switch(sw_name=sw_name,
                                addr=f'{ip}:{grpc_port}',
                                device_id=device_id,
                                sw_conf_file=sw_conf_file,
                                workdir=os.getcwd(),
                                proto_dump_fpath=outfile)

    def program_switches(self):
        for sw_name, sw_dict in self.switches.items():
            if 'runtime_json' in sw_dict:
                self.program_switch_p4runtime(sw_name, sw_dict)

    def packet_in_handler(self, sw_name, sw_params):
        while True:
            packet_in = None
            try:
                packet_in = sw_params['connection'].PacketIn()
            except Exception as e:
                self.logger("Exception in packet in thread. If you are leaving the program is Ok")
                self.logger(e)
                break
            if packet_in:
                packet_in_thread = Thread(target=self.packet_in_action, kwargs={'sw_name': sw_name, 'packet_in': packet_in})
                packet_in_thread.start()

    def packet_in_action(self, sw_name, packet_in):
        self.logger("Switch %s packet in!" % sw_name)
        # TODO 13. Detecting ARP and IP
        # Set default action as send_to_ctrl in sw_config.json file to change the default settings of the switch
        pkt = Ether(packet_in.packet.payload)
        if 'ARP' in pkt:
            src_ip = pkt['ARP'].psrc
            dst_ip = pkt['ARP'].pdst
            src_host = self.find_host_by_addr(src_ip, 'ip')
            dst_host = self.find_host_by_addr(dst_ip, 'ip')
            self.logger(
                f"ARP packet. Src. ip: {src_ip}, dst. ip: {dst_ip}, src. host: {src_host}, dst. host: {dst_host}")
            # TODO 14. Shortest path computation and deployment.
            # Uncomment this line after TODO 14
            self.install_bidirectional_flow(src_host, dst_host, src_ip, dst_ip, pkt)
        elif 'IP' in pkt:
            src_ip = pkt['IP'].src
            dst_ip = pkt['IP'].dst
            src_host = self.find_host_by_addr(src_ip, 'ip')
            dst_host = self.find_host_by_addr(dst_ip, 'ip')
            self.logger(
                f"IP packet. Src. ip: {src_ip}, dst. ip: {dst_ip}, src. host: {src_host}, dst. host: {dst_host}")
        #     TODO 14. Shortest path computation and deployment.
        #     # Uncomment this line after TODO 14
            self.install_bidirectional_flow(src_host, dst_host, src_ip, dst_ip, pkt)
        else:
            return

    def install_bidirectional_flow(self, src_host, dst_host, src_ip, dst_ip, pkt):
        # TODO 14: Shortest path computation and deployment
        path = self.path_handler(src_host, dst_host)
        if path:
            # go path -->
            for index in range(1, len(path)-1, 1):
                current_sw = path[index]
                next_sw = path[index+1]
                out_port = self.topology.get_edge_data(current_sw, next_sw)['anchors'][current_sw].replace('eth', '')
                self.install_ipv4_exact_rule(current_sw, out_port, src_ip, dst_ip)
            # return path <--
            for index in range(len(path)-2, 0, -1):
                current_sw = path[index]
                next_sw = path[index-1]
                out_port = self.topology.get_edge_data(current_sw, next_sw)['anchors'][current_sw].replace('eth', '')
                self.install_ipv4_exact_rule(current_sw, out_port, dst_ip, src_ip)

            # TODO 16:  Sending the first-packet in.
            # Packet out in last switch
            last_sw = path[-2]
            out_port = self.topology.get_edge_data(last_sw, dst_host)['anchors'][last_sw].replace('eth', '')
            pkt_out = self.build_packet_out(pkt, out_port)
            self.switches[last_sw]['connection'].PacketOut(pkt_out)
        else:
            self.logger("Skipping path deployment")

    def path_handler(self, src_host, dst_host):
        if self.topology.has_node(src_host) and self.topology.has_node(dst_host):
            path = nx.shortest_path(self.topology, source=src_host, target=dst_host)
            self.logger(f"Path between {src_host} and {dst_host} is {path}")
            return path
        else:
            self.logger(f"Ups path between {src_host} and {dst_host} not found")
            return []

    def build_packet_out(self, pkt, out_port):
        pkt_out = PacketOut()
        pkt_out.payload = bytes(pkt)
        egress_port = pkt_out.metadata.add()
        egress_port.metadata_id = 1
        egress_port.value = self.stringify(int(out_port), 2)
        return pkt_out

    def stringify(self, n, length):
        h = '%x' % n
        s = ('0' * (len(h) % 2) + h).zfill(length * 2)
        return bytes.fromhex(s)

    def find_host_by_addr(self, addr, addr_type):
        for node in self.topology.nodes:
            if self.topology.nodes[node][addr_type] == addr:
                self.logger("Node %s with address %s is in topology" % (node, addr))
                return node
        self.logger("Address %s not found" % addr)
        return False

    def install_ipv4_exact_rule(self, sw_name, out_port, src_ip, dst_ip):
        table_entry = self.switches[sw_name]['helper'].buildTableEntry(
            table_name="MyIngress.ipv4_exact",
            match_fields={
                "meta.src_ipv4": [src_ip],
                "meta.dst_ipv4": [dst_ip],
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "port": int(out_port)
            }
        )
        self.logger("Installing l3 rule on %s. Src ip: %s dst ip %s out port %s" % (sw_name, src_ip, dst_ip, out_port))
        self.switches[sw_name]['connection'].WriteTableEntry(table_entry)

    def start_packet_in_manager(self):
        for sw_name, sw_params in self.switches.items():
            packet_in_thread = Thread(target=self.packet_in_handler, daemon=True, args=(sw_name, sw_params, ))
            self.switches[sw_name]['thread'] = packet_in_thread
            self.logger("Starting packet in handler for %s" % sw_name)
            packet_in_thread.start()

    def error(self, msg):
        print(' - ERROR! ' + msg, file=sys.stderr)

    def info(self, msg):
        print(' - ' + msg, file=sys.stdout)

    def check_switch_conf(self, sw_conf, workdir):
        required_keys = ["p4info"]
        files_to_check = ["p4info"]
        target_choices = ["bmv2"]

        if "target" not in sw_conf:
            raise ConfException("missing key 'target'")
        target = sw_conf['target']
        if target not in target_choices:
            raise ConfException("unknown target '%s'" % target)

        if target == 'bmv2':
            required_keys.append("bmv2_json")
            files_to_check.append("bmv2_json")

        for conf_key in required_keys:
            if conf_key not in sw_conf or len(sw_conf[conf_key]) == 0:
                raise ConfException("missing key '%s' or empty value" % conf_key)

        for conf_key in files_to_check:
            real_path = os.path.join(workdir, sw_conf[conf_key])
            if not os.path.exists(real_path):
                raise ConfException("file does not exist %s" % real_path)

    def program_switch(self, addr, device_id, sw_conf_file, workdir, proto_dump_fpath, sw_name):
        sw_conf = self.json_load_byteified(sw_conf_file)
        try:
            self.check_switch_conf(sw_conf=sw_conf, workdir=workdir)
        except ConfException as e:
            self.error("While parsing input runtime configuration: %s" % str(e))
            return

        self.info('Using P4Info file %s...' % sw_conf['p4info'])
        p4info_fpath = os.path.join(workdir, sw_conf['p4info'])
        p4info_helper = helper.P4InfoHelper(p4info_fpath)

        target = sw_conf['target']

        self.info("Connecting to P4Runtime server on %s (%s)..." % (addr, target))

        if target == "bmv2":
            sw = bmv2.Bmv2SwitchConnection(name=sw_name, address=addr, device_id=device_id,
                                           proto_dump_file=proto_dump_fpath)
        else:
            raise Exception("Don't know how to connect to target %s" % target)

        try:
            sw.MasterArbitrationUpdate()

            if target == "bmv2":
                self.info("Setting pipeline config (%s)..." % sw_conf['bmv2_json'])
                bmv2_json_fpath = os.path.join(workdir, sw_conf['bmv2_json'])
                sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                               bmv2_json_file_path=bmv2_json_fpath)
                # Storing switch connection object
                # Connection is also stored in switch dependency
                self.switches[sw_name].update({'connection': sw})
                self.switches[sw_name].update({'helper': p4info_helper})
            else:
                raise Exception("Should not be here")

            if 'table_entries' in sw_conf:
                table_entries = sw_conf['table_entries']
                self.info("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    self.info(self.tableEntryToString(entry))
                    self.insertTableEntry(sw, entry, p4info_helper)

            if 'multicast_group_entries' in sw_conf:
                group_entries = sw_conf['multicast_group_entries']
                self.info("Inserting %d group entries..." % len(group_entries))
                for entry in group_entries:
                    self.info(self.groupEntryToString(entry))
                    self.insertMulticastGroupEntry(sw, entry, p4info_helper)

            if 'clone_session_entries' in sw_conf:
                clone_entries = sw_conf['clone_session_entries']
                self.info("Inserting %d clone entries..." % len(clone_entries))
                for entry in clone_entries:
                    self.info(self.cloneEntryToString(entry))
                    self.insertCloneGroupEntry(sw, entry, p4info_helper)

        except Exception as e:
            # Close connection if something fails otherwise keep it
            self.logger("Exception %e " % e)
            sw.shutdown()

    def insertTableEntry(self, sw, flow, p4info_helper):
        table_name = flow['table']
        match_fields = flow.get('match') # None if not found
        action_name = flow['action_name']
        default_action = flow.get('default_action') # None if not found
        action_params = flow['action_params']
        priority = flow.get('priority')  # None if not found

        table_entry = p4info_helper.buildTableEntry(
            table_name=table_name,
            match_fields=match_fields,
            default_action=default_action,
            action_name=action_name,
            action_params=action_params,
            priority=priority)

        sw.WriteTableEntry(table_entry)

    def json_load_byteified(self, file_handle):
        return json.load(file_handle)

    def _byteify(self, data, ignore_dicts=False):
        # if this is a unicode string, return its string representation
        if isinstance(data, str):
            return data.encode('utf-8')
        # if this is a list of values, return list of byteified values
        if isinstance(data, list):
            return [self._byteify(item, ignore_dicts=True) for item in data]
        # if this is a dictionary, return dictionary of byteified keys and values
        # but only if we haven't already byteified it
        if isinstance(data, dict) and not ignore_dicts:
            return {
                self._byteify(key, ignore_dicts=True): self._byteify(value, ignore_dicts=True)
                for key, value in data.items()
            }
        # if it's anything else, return it in its original form
        return data

    def tableEntryToString(self, flow):
        if 'match' in flow:
            match_str = ['%s=%s' % (match_name, str(flow['match'][match_name])) for match_name in
                         flow['match']]
            match_str = ', '.join(match_str)
        elif 'default_action' in flow and flow['default_action']:
            match_str = '(default action)'
        else:
            match_str = '(any)'
        params = ['%s=%s' % (param_name, str(flow['action_params'][param_name])) for param_name in
                  flow['action_params']]
        params = ', '.join(params)
        return "%s: %s => %s(%s)" % (
            flow['table'], match_str, flow['action_name'], params)

    def groupEntryToString(self, rule):
        group_id = rule["multicast_group_id"]
        replicas = ['%d' % replica["egress_port"] for replica in rule['replicas']]
        ports_str = ', '.join(replicas)
        return 'Group {0} => ({1})'.format(group_id, ports_str)

    def cloneEntryToString(self, rule):
        clone_id = rule["clone_session_id"]
        if "packet_length_bytes" in rule:
            packet_length_bytes = str(rule["packet_length_bytes"])+"B"
        else:
            packet_length_bytes = "NO_TRUNCATION"
        replicas = ['%d' % replica["egress_port"] for replica in rule['replicas']]
        ports_str = ', '.join(replicas)
        return 'Clone Session {0} => ({1}) ({2})'.format(clone_id, ports_str, packet_length_bytes)

    def insertMulticastGroupEntry(self, sw, rule, p4info_helper):
        mc_entry = p4info_helper.buildMulticastGroupEntry(rule["multicast_group_id"], rule['replicas'])
        sw.WritePREEntry(mc_entry)

    def insertCloneGroupEntry(self, sw, rule, p4info_helper):
        clone_entry = p4info_helper.buildCloneSessionEntry(rule['clone_session_id'], rule['replicas'],
                                                           rule.get('packet_length_bytes', 0))
        sw.WritePREEntry(clone_entry)
