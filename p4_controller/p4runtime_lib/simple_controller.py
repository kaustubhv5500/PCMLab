#!/usr/bin/env python3
#
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import json
import os
import sys
import random
import time

from . import bmv2
from . import helper
from threading import Thread

from scapy.all import Ether, IP, TCP
import networkx as nx


class ConfException(Exception):
    pass


class P4RuntimeController:
    challenge_width = 32
    complexity_mask_width = 32

    def __init__(self, switches, hosts, links, network, quiet, log_dir, pow_compl, pow_upd_int):
        self.network = network
        self.quiet = quiet
        self.log_dir = log_dir
        # Switches should be a class instead of a dict
        self.switches = switches
        self.hosts = hosts
        self.links = links
        self.topology = nx.Graph()
        self.init_topology()
        self.pow_complexity = pow_compl
        self.complexity_mask, _ = self.generate_mask(pow_compl)
        self.pow_update_interval = pow_upd_int
        self.pow_challenge_service_thread = None


    def init_topology(self):

        for host_name, host_params in self.hosts.items():
            self.topology.add_node(host_name, ip=host_params['ip'].split('/')[0], mac=host_params['mac'])

        for switch_name in self.switches.keys():
            self.topology.add_node(switch_name, ip='', mac='')

        for link in self.links:
            node1, node1_port = self.get_node_port(link["node1"])
            node2, node2_port = self.get_node_port(link["node2"])
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

    def program_switch_p4runtime(self, sw_name, sw_dict):
        """ This method will use P4Runtime to program the switch using the
            content of the runtime JSON file as input.
        """
        sw_obj = self.network.get(sw_name)
        grpc_port = sw_obj.grpc_port
        device_id = sw_obj.device_id
        runtime_json = sw_dict['runtime_json']
        self.logger('Configuring switch %s using P4Runtime with file %s' % (sw_name, runtime_json))
        with open(runtime_json, 'r') as sw_conf_file:
            outfile = '%s/%s-p4runtime-requests.txt' % (self.log_dir, sw_name)
            self.program_switch(sw_name=sw_name,
                                addr='127.0.0.1:%d' % grpc_port,
                                device_id=device_id,
                                sw_conf_file=sw_conf_file,
                                workdir=os.getcwd(),
                                proto_dump_fpath=outfile)

    def program_switches(self):
        """ This method will program each switch using the BMv2 P4Runtime,
            depending if any runtime JSON files were
            provided for the switches.
        """
        for sw_name, sw_dict in self.switches.items():
            if 'runtime_json' in sw_dict:
                self.program_switch_p4runtime(sw_name, sw_dict)

    def program_hosts(self):
        """ Execute any commands provided in the topology.json file on each Mininet host
        """
        for host_name, host_info in list(self.hosts.items()):
            h = self.network.get(host_name)
            if "commands" in host_info:
                for cmd in host_info["commands"]:
                    h.cmd(cmd)

    def packet_in_handler(self, sw_name, sw_params):
        while True:
            packet_in = None
            try:
                packet_in = sw_params['connection'].PacketIn()
            except Exception as e:
                print("Exception in packet in thread. If you are leaving the program is Ok")
                print(e)
                break
            if packet_in:
                self.logger("Switch %s packet in!" % sw_name)
                self.logger("%s" % packet_in)
                print(type(packet_in))
                pkt = Ether(packet_in.packet.payload)
                print(pkt.show())
                layer = 2
                src_mac = pkt[Ether].src
                dst_mac = pkt[Ether].dst
                src_ip = None
                dst_ip = None
                sport_tcp = None
                dport_tcp = None
                src_host = None
                dst_host = None
                if IP in pkt:
                    layer = 3
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                if TCP in pkt:
                    layer = 4
                    sport_tcp = pkt[TCP].sport
                    dport_tcp = pkt[TCP].dport

                if 3 <= layer <= 4:
                    src_host = self.find_host_by_addr(src_ip, 'ip')
                    dst_host = self.find_host_by_addr(dst_ip, 'ip')
                else:
                    src_host = self.find_host_by_addr(src_mac, 'mac')
                    dst_host = self.find_host_by_addr(dst_mac, 'mac')

                print("Layer: %s src_host: %s dst_host %s src_mac: %s dst_mac: %s src_ip: %s dst_ip: %s sport: %s dport: %s" %
                      (layer, src_host, dst_host, src_mac, dst_mac, src_ip, dst_ip, sport_tcp, dport_tcp))

                if src_host and dst_host:
                    self.install_bidirectional_flow(layer, src_host, dst_host, src_mac, dst_mac,
                                                    src_ip, dst_ip, sport_tcp, dport_tcp)
                else:
                    print("Unknown destination")

    def install_bidirectional_flow(self, layer, src_host, dst_host, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port):
        path = nx.shortest_path(self.topology, source=src_host, target=dst_host)
        if path:
            # go path ->
            for index in range(1, len(path)-1, 1):
                current_sw = path[index]
                next_sw = path[index + 1]
                out_port = self.topology.get_edge_data(current_sw, next_sw)['anchors'][current_sw].replace('p', '')
                if layer == 4:
                    self.install_l4_forwaring_rule(current_sw, out_port, src_ip, dst_ip, src_port, dst_port)
                elif layer == 3:
                    self.install_l3_forwaring_rule(current_sw, out_port, src_ip, dst_ip)
                else:
                    self.install_l2_forwaring_rule(current_sw, out_port, src_mac, dst_mac)
            # return path <-
            for index in range(-2, -len(path), -1):
                current_sw = path[index]
                next_sw = path[index - 1]
                out_port = self.topology.get_edge_data(current_sw, next_sw)['anchors'][current_sw].replace('p', '')
                if layer == 4:
                    self.install_l4_forwaring_rule(current_sw, out_port, dst_ip, src_ip, dst_port, src_port)
                elif layer == 3:
                    self.install_l3_forwaring_rule(current_sw, out_port, dst_ip, src_ip)
                else:
                    self.install_l2_forwaring_rule(current_sw, out_port, dst_mac, src_mac)
        else:
            print("Ups path not found")

    def find_host_by_addr(self, addr, addr_type):
        for node in self.topology.nodes:
            if self.topology.nodes[node][addr_type] == addr:
                print("Node %s with address %s is in topology" % (node, addr))
                return node
        print("Address %s not found" % addr)
        return False

    def install_l2_forwaring_rule(self, sw_name, out_port, src_mac, dst_mac):
        table_entry = self.switches[sw_name]['helper'].buildTableEntry(
            table_name="MyIngress.l2_exact",
            match_fields={
                "hdr.ethernet.srcAddr": src_mac,
                "hdr.ethernet.dstAddr": dst_mac
            },
            action_name="MyIngress.l2_forward",
            action_params={
                "port": int(out_port)
            }
        )
        print("Installing l2 rule on %s. Src mac: %s dst mac %s out port %s" % (sw_name, src_mac, dst_mac, out_port))
        self.switches[sw_name]['connection'].WriteTableEntry(table_entry)

    def install_l3_forwaring_rule(self, sw_name, out_port, src_ip, dst_ip):
        table_entry = self.switches[sw_name]['helper'].buildTableEntry(
            table_name="MyIngress.l3_exact",
            match_fields={
                "hdr.ipv4.srcAddr": src_ip,
                "hdr.ipv4.dstAddr": dst_ip
            },
            action_name="MyIngress.l3_forward",
            action_params={
                "port": int(out_port)
            }
        )
        print("Installing l3 rule on %s. Src ip: %s dst ip %s out port %s" % (sw_name, src_ip, dst_ip, out_port))
        self.switches[sw_name]['connection'].WriteTableEntry(table_entry)

    def install_l4_forwaring_rule(self, sw_name, out_port, src_ip, dst_ip, src_tcp_port, dst_tcp_port):
        table_entry = self.switches[sw_name]['helper'].buildTableEntry(
            table_name="MyIngress.l4_exact",
            match_fields={
                "hdr.ipv4.srcAddr": src_ip,
                "hdr.ipv4.dstAddr": dst_ip,
                "hdr.tcp.srcPort": int(src_tcp_port),
                "hdr.tcp.dstPort": int(dst_tcp_port)
            },
            action_name="MyIngress.l4_forward",
            action_params={
                "port": int(out_port)
            }
        )
        print("Installing l4 rule on %s. Src ip: %s dst ip %s src port %s dst port %s out port %s" %
              (sw_name, src_ip, dst_ip, src_tcp_port, dst_tcp_port, out_port))
        self.switches[sw_name]['connection'].WriteTableEntry(table_entry)

    def start_packet_in_manager(self):
        for sw_name, sw_params in self.switches.items():
            packet_in_thread = Thread(target=self.packet_in_handler, daemon=True, args=(sw_name, sw_params, ))
            self.switches[sw_name]['thread'] = packet_in_thread
            print("Starting packet in handler for %s" % sw_name)
            packet_in_thread.start()

    def install_challenge_rule(self, sw_name, layer, complexity, complexity_mask, challenge, action):
        table_entry = self.switches[sw_name]['helper'].buildTableEntry(
            table_name="MyIngress.pow_check",
            match_fields={
                "meta.layer": int(layer),
            },
            action_name="MyIngress.l%s_pow" % layer,
            action_params={
                "complexity": int(complexity),
                "complexity_mask": int(complexity_mask),
                "challenge": int(challenge)
            }
        )
        print("%s l%s challenge rule on %s. Complexity: %s complexity mask %s challenge %s" %
              (action, layer, sw_name, complexity, complexity_mask, challenge))
        if action == "insert":
            self.switches[sw_name]['connection'].WriteTableEntry(table_entry)
        elif action == "delete":
            self.switches[sw_name]['connection'].DeleteTableEntry(table_entry)
        else:
            print("Unknown action")

    def default_bounce(self, sw_name, layer):
        table_entry = self.switches[sw_name]['helper'].buildTableEntry(
            table_name="MyIngress.bounce",
            match_fields={
                "meta.layer": int(layer),
            },
            action_name="MyIngress.l%s_bounce_packet" % layer,
            action_params={}
        )
        print("Installing default bounce rule for layer %s on %s" % (layer, sw_name))
        self.switches[sw_name]['connection'].WriteTableEntry(table_entry)

    def set_drop_as_default(self, sw_name, table_name):
        table_entry = self.switches[sw_name]['helper'].buildTableEntry(
            table_name="MyIngress.%s" % table_name,
            default_action=True,
            action_name="MyIngress.drop",
            action_params={}
        )
        print("Installing default action for table %s on %s" % (table_name, sw_name))
        self.switches[sw_name]['connection'].WriteTableEntry(table_entry)

    def install_default_rules(self):
        table_names = ["l2_exact", "l3_exact", "l4_exact", "pow_check", "bounce"]

        for sw_name in self.switches.keys():

            # Set drop as default action in all SWs
            for table_name in table_names:
                self.set_drop_as_default(sw_name, table_name)

            # Set bounce rule for each layer.
            for layer in range(2, 5):
                self.default_bounce(sw_name, layer)

    def pow_challenge_service(self):
        l2_challenge = None
        l3_challenge = None
        l4_challenge = None
        something_to_delete = False
        while True:
            for sw_name, sw_params in self.switches.items():
                # Delete the previous rule
                if something_to_delete:
                    self.install_challenge_rule(sw_name, 2, self.pow_complexity, self.complexity_mask, l2_challenge, "delete")
                    self.install_challenge_rule(sw_name, 3, self.pow_complexity, self.complexity_mask, l3_challenge, "delete")
                    self.install_challenge_rule(sw_name, 4, self.pow_complexity, self.complexity_mask, l4_challenge, "delete")
                # Update PoW challenge rule
                l2_challenge = random.randint(0, 2 ** P4RuntimeController.challenge_width - 1)
                self.install_challenge_rule(sw_name, 2, self.pow_complexity, self.complexity_mask, l2_challenge, "insert")
                l3_challenge = random.randint(0, 2 ** P4RuntimeController.challenge_width - 1)
                self.install_challenge_rule(sw_name, 3, self.pow_complexity, self.complexity_mask, l3_challenge, "insert")
                l4_challenge = random.randint(0, 2 ** P4RuntimeController.challenge_width - 1)
                self.install_challenge_rule(sw_name, 4, self.pow_complexity, self.complexity_mask, l4_challenge, "insert")
            something_to_delete = True
            time.sleep(self.pow_update_interval)

    def start_pow_challenge_service(self):
        self.pow_challenge_service_thread = Thread(target=self.pow_challenge_service, daemon=True)
        print("Staring PoW challenge service")
        self.pow_challenge_service_thread.start()

    def str_to_hex(self, number, field_width):
        width = int(field_width / 4)
        return "{0:0{1}X}".format(int(number), width)

    def generate_mask(self, complexity):
        complexity_mask_str = str(((1 << complexity) - 1) << P4RuntimeController.complexity_mask_width - complexity)
        complexity_mask_hex_str = self.str_to_hex(complexity_mask_str, P4RuntimeController.complexity_mask_width)
        return complexity_mask_str, complexity_mask_hex_str

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
            print("Exception %e " % e)
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
