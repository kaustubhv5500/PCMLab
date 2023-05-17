from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.topology import event as topo_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, tcp
from ryu.lib.packet import ether_types
from ryu.lib import hub
# TODO 4. Creating the network graph
import networkx as nx
from random import randint


class Switch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch13, self).__init__(*args, **kwargs)

        # TODO 4. Creating the network graph
        self.network = nx.DiGraph()
        self.MONITOR_PERIOD = 30
        self.monitor_thread = hub.spawn(self.monitor)

        # TODO 5. Adding the switches and links
        self.SWITCH_TYPE = "switch"

        # TODO 6. Detecting the hosts
        self.DEFAULT_TABLE = 0
        self.LOW_PRIORITY = 0
        self.MEDIUM_PRIORITY = 50
        self.HIGH_PRIORITY = 100
        self.HARD_TIMEOUT = 60
        self.IDLE_TIMEOUT = 60

        # TODO 7. Adding the hosts and links
        self.HOST_TYPE = "host"
        # Assumes hosts use eth1 as port.
        self.DEFAULT_HOST_PORT = 1

        # TODO 9. ARP network access
        self.IP_ICMP = 0X01
        self.IP_TCP = 0x06
        self.TCP_HTTP = 0x50
        self.TCP_SSH = 0x16
        self.access_dict = {
            "10.0.0.1": {
                "hosts": ["10.0.0.2", "10.0.0.5", "10.0.0.6"],
                "protocols": [ether_types.ETH_TYPE_ARP, self.IP_ICMP, self.TCP_SSH, self.TCP_HTTP]
            },
            "10.0.0.2": {
                "hosts": ["10.0.0.1","10.0.0.5","10.0.0.6"],
                "protocols": [ether_types.ETH_TYPE_ARP, self.IP_ICMP, self.TCP_SSH, self.TCP_HTTP]
            },
            "10.0.0.3": {
                "hosts": ["10.0.0.4", "10.0.0.7", "10.0.0.8"],
                "protocols": [ether_types.ETH_TYPE_ARP, self.IP_ICMP, self.TCP_HTTP]
            },
            "10.0.0.4": {
                "hosts": ["10.0.0.3","10.0.0.7","10.0.0.8"],
                "protocols": [ether_types.ETH_TYPE_ARP, self.IP_ICMP, self.TCP_HTTP]
            },
            "10.0.0.5": {
                "hosts": ["10.0.0.1","10.0.0.2","10.0.0.6"],
                "protocols": [ether_types.ETH_TYPE_ARP, self.IP_ICMP, self.TCP_SSH, self.TCP_HTTP]
            },
            "10.0.0.6": {
                "hosts": ["10.0.0.1","10.0.0.2","10.0.0.5"],
                "protocols": [ether_types.ETH_TYPE_ARP, self.IP_ICMP, self.TCP_SSH, self.TCP_HTTP]
            },
            "10.0.0.7": {
                "hosts": ["10.0.0.3","10.0.0.4","10.0.0.8"],
                "protocols": [ether_types.ETH_TYPE_ARP, self.IP_ICMP, self.TCP_HTTP]
            },
            "10.0.0.8": {
                "hosts": ["10.0.0.3","10.0.0.4","10.0.0.7"],
                "protocols": [ether_types.ETH_TYPE_ARP, self.IP_ICMP, self.TCP_HTTP]
            }
        }

        # TODO 20. Shortest path for ICMP traffic
        self.core_edges_list = [(1,7), (7,1), (1,8), (8,1), (1,9), (9,1),
                                (4,7), (7,4), (8,4), (4,8), (9,4), (4,9)]
        self.edge_cost_range = (1, 10)
        self.DEFAULT_EDGE_WEIGHT = 1

        # TODO 29. Retrieving flow stats
        # self.stats_poller_thread = hub.spawn(self.poll_switch_load)
        # self.NUM_FLOWS_SORT = "num_flows"
        # self.TX_PKTS_SORT = "tx_pkts"

    @set_ev_cls(topo_event.EventSwitchEnter, MAIN_DISPATCHER)
    def new_switch_handler(self, ev):
        switch = ev.switch
        dp = switch.dp
        dpid = dp.id
        self.logger.info(f"Switch s{dpid} detected")

        # TODO 5. Adding the switches and links
        self.network.add_node(dpid, type=self.SWITCH_TYPE, name=f"s{dpid}", dp=dp, tx_pkts=0, num_flows=0)

        # TODO 6. Detecting the hosts: When a new switch is detected, set the default action as Controller
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(dp=dp, table=self.DEFAULT_TABLE, priority=self.LOW_PRIORITY, match=match, actions=actions)

    @set_ev_cls(topo_event.EventLinkAdd, MAIN_DISPATCHER)
    def new_link_handler(self, ev):
        link = ev.link
        src = link.src.dpid
        src_port = link.src.port_no
        dst = link.dst.dpid
        dst_port = link.dst.port_no
        self.logger.info(f"Link s{src} <--> s{dst} detected")

        # TODO 5. Adding the switches and links
        # Add links in both directions as the graph object is not directional by default
        self.network.add_edge(src, dst, src_port=src_port, dst_port=dst_port)
        self.network.add_edge(dst, src, src_port=dst_port, dst_port=src_port)

    @set_ev_cls(topo_event.EventHostAdd, MAIN_DISPATCHER)
    def new_host_handler(self, ev):
        host = ev.host
        host_ipv4 = host.ipv4[0]
        host_mac = host.mac
        dpid = host.port.dpid
        dpid_port = host.port.port_no
        self.logger.info(f"Host {host_ipv4} detected")

        # TODO 7. Adding the hosts and links
        self.network.add_node(host_ipv4, type=self.HOST_TYPE, mac=host_mac)
        self.network.add_edge(host_ipv4, dpid, src_port=self.DEFAULT_HOST_PORT, dst_port=dpid_port)
        self.network.add_edge(dpid, host_ipv4, src_port=dpid_port, dst_port=self.DEFAULT_HOST_PORT)

    def monitor(self):
        while True:
            self.logger.info("Printing topology information")
            for node1, node2, data in self.network.edges(data=True):
                node1_str = str(node1)
                node2_str = str(node2)
                # If the name includes a dot, it is an IP address, thus a host
                if '.' in node1_str:
                    node1_str = f"h{node1_str}"
                else:
                    node1_str = f"s{node1_str}"
                if '.' in node2_str:
                    node2_str = f"h{node2_str}"
                else:
                    node2_str = f"s{node2_str}"
                self.logger.info(f"{node1_str}-eth{data['src_port']} --> {node2_str}-eth{data['dst_port']}")
            hub.sleep(self.MONITOR_PERIOD)

    def add_flow(self, dp, table, priority, match, actions=None, buffer_id=None, i_tout=0, h_tout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=dp, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table,
                                    idle_timeout=i_tout, hard_timeout=h_tout)
        else:
            mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                    match=match, instructions=inst, table_id=table,
                                    idle_timeout=i_tout, hard_timeout=h_tout)

        dp.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Lots of packets that's why this statement is commented
        # self.logger.info("Packet in!!!!!")
        # Extracts switch info
        dp = ev.msg.datapath
        dpid = dp.id
        in_port = ev.msg.match['in_port']
        # Extracts OF handlers
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        # Extracts the packet
        pkt_in = packet.Packet(ev.msg.data)
        eth_header = pkt_in.get_protocols(ethernet.ethernet)[0]
        dst_mac = eth_header.dst
        src_mac = eth_header.src
        ethertype = eth_header.ethertype

        if ethertype == ether_types.ETH_TYPE_LLDP:
            # There are many LLDP packets being exchanged.
            # That is why this print statement is being commented
            # self.logger.info('Ignoring LLDP')
            return

        # TODO 8. Detecting ARP traffic
        if ethertype == ether_types.ETH_TYPE_ARP:
            arp_header = pkt_in.get_protocols(arp.arp)[0]
            self.arp_handler(dp=dp, parser=parser, proto=ether_types.ETH_TYPE_ARP, arp_header=arp_header, ev=ev)
            return

        # TODO 17. Detecting ICMP traffic
        ip_header = pkt_in.get_protocols(ipv4.ipv4)[0]
        ip_proto = ip_header.proto
        if ip_proto == self.IP_ICMP:
            self.ip_handler(dp=dp, parser=parser, proto=self.IP_ICMP, ip_header=ip_header, ev=ev)

        # TODO 23. Detecting TCP traffic
        elif ip_proto == self.IP_TCP:
            tcp_header = pkt_in.get_protocols(tcp.tcp)[0]
            self.tcp_handler(dp=dp, parser=parser, proto=self.IP_TCP, ip_header=ip_header, tcp_header=tcp_header, ev=ev)

    def arp_handler(self, dp, parser,  proto, arp_header, ev):
        self.logger.info("ARP packet!")
        # TODO 9. ARP network access
        src_ip = arp_header.src_ip
        dst_ip = arp_header.dst_ip
        accces_status = self.access_handler(src_ip=src_ip, dst_ip=dst_ip, proto=proto)

        # TODO 10. Blocking ARP traffic
        # Keep the body of the if statement only with the pass statement during TODO 10
        # Focus only in the else statement during TODO 10
        if accces_status:
             # pass  # Comment in TODO 14
            # TODO 14. Shortest path for ARP traffic
            # Get the shortest path
            shortest_path = self.path_handler(src_ip=src_ip, dst_ip=dst_ip)

            # TODO 15. Routing for ARP traffic
            if shortest_path:
                # Install the rule in every switch of the path
                for index, link in enumerate(shortest_path):
                    src_sw, dst_sw = link
                    hop_dp = self.network.nodes[src_sw]["dp"]
                    match = parser.OFPMatch(eth_type=proto, arp_spa=src_ip, arp_tpa=dst_ip)
                    out_port = self.network.get_edge_data(src_sw, dst_sw)["src_port"]
                    actions = [parser.OFPActionOutput(out_port)]
                    self.logger.info(f"DP: {hop_dp.id}, Match: [Eth. proto: {proto} src IP: {src_ip} dst IP: {dst_ip}], Out port: {out_port}")
                    self.add_flow(dp=hop_dp, table=self.DEFAULT_TABLE, priority=self.HIGH_PRIORITY, match=match, actions=actions)

                    # TODO 16. Forwarding initial ARP packet
                    # Output the packet in the last switch of the path
                    if index == len(shortest_path) - 1:
                        in_port = self.network.get_edge_data(src_sw, dst_sw)["dst_port"]
                        self.logger.info(f"Pkt-out DP: {hop_dp.id}, in-port: {in_port}, out-port: {out_port}")
                        out = parser.OFPPacketOut(datapath=hop_dp, buffer_id=ev.msg.buffer_id, in_port=in_port, actions=actions, data=ev.msg.data)
                        hop_dp.send_msg(out)
        else:
            match = parser.OFPMatch(eth_type=proto, arp_spa=src_ip, arp_tpa=dst_ip)
            # Drop the packet by performing no action on it
            actions = []
            self.logger.info(f"DP: {dp.id}, Match: [Eth. proto: {proto} src IP: {src_ip} dst IP: {dst_ip}], Out port: [Block]")
            # self.add_flow(dp=dp, table=self.DEFAULT_TABLE, priority=self.LOW_PRIORITY, match=match, actions=actions)
            # TODO 11. Rule priority
            # Comment previous call to add flow. Install the same rule with medium priority
            # self.add_flow(dp=dp, table=self.DEFAULT_TABLE, priority=self.MEDIUM_PRIORITY, match=match, actions=actions)
            # TODO 12. Idle timeout
            # Comment previous call to add flow. Install the same rule with an idle timeout
            # self.add_flow(dp=dp, table=self.DEFAULT_TABLE, priority=self.MEDIUM_PRIORITY, match=match, actions=actions, i_tout=self.IDLE_TIMEOUT)
            # TODO 13. Hard timeout
            # Comment previous call to add flow. Install the same rule replacing the  idle timeout with a hard timeout
            self.add_flow(dp=dp, table=self.DEFAULT_TABLE, priority=self.MEDIUM_PRIORITY, match=match, actions=actions, h_tout=self.HARD_TIMEOUT)

    def ip_handler(self, dp, parser, proto, ip_header, ev):
        self.logger.info("ICMP packet!")

        # TODO 18. ICMP network access
        src_ip = ip_header.src
        dst_ip = ip_header.dst
        access_status = self.access_handler(src_ip=src_ip, dst_ip=dst_ip, proto=proto)

        # TODO 19. Blocking ICMP traffic.
        if access_status:
            # Keep the body of the if statement only with the pass statement during TODO 19
            # Focus only in the else statement during TODO 19
            # pass  # Comment me in TODO 20
            # TODO 20. Shortest path for ICMP traffic
            shortest_path = self.path_handler(src_ip=src_ip, dst_ip=dst_ip, weight_func=self.load_balancer)
            # TODO 21. Routing for ICMP traffic
            if shortest_path:
                for index, link in enumerate(shortest_path):
                    src_sw, dst_sw = link
                    hop_dp = self.network.nodes[src_sw]['dp']
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=proto, ipv4_src=src_ip, ipv4_dst=dst_ip)
                    out_port = self.network.get_edge_data(src_sw, dst_sw)["src_port"]
                    actions = [parser.OFPActionOutput(out_port)]
                    self.logger.info(f"DP: {hop_dp.id}, Match: [IP proto: {proto} src IP: {src_ip} dst IP: {dst_ip}], Out port: {out_port}")
                    self.add_flow(dp=hop_dp, table=self.DEFAULT_TABLE, priority=self.HIGH_PRIORITY, match=match, actions=actions)

                    # TODO 22. Forwarding initial ICMP packet
                    if index == len(shortest_path) - 1:
                         in_port = self.network.get_edge_data(src_sw, dst_sw)["dst_port"]
                         self.logger.info(f"Pkt-out DP: {hop_dp.id}, in-port: {in_port}, out-port: {out_port}")
                         out = parser.OFPPacketOut(datapath=hop_dp, buffer_id=ev.msg.buffer_id, in_port=in_port, actions=actions, data=ev.msg.data)
                         hop_dp.send_msg(out)
        else:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=proto, ipv4_src=src_ip, ipv4_dst=dst_ip)
            actions = []
            self.logger.info(f"DP: {dp.id}, Match: [IP proto: {proto} src IP: {src_ip} dst IP: {dst_ip}], Out port: [Block]")
            self.add_flow(dp=dp, table=self.DEFAULT_TABLE, priority=self.MEDIUM_PRIORITY, match=match, actions=actions, h_tout=self.HARD_TIMEOUT)

    def tcp_handler(self, dp, parser,  proto, ip_header, tcp_header, ev):
        self.logger.info("TCP packet!")

        # TODO 24. TCP network access
        src_ip = ip_header.src
        dst_ip = ip_header.dst
        src_port = tcp_header.src_port
        dst_port = tcp_header.dst_port
        tcp_proto = self.tcp_proto_selector(src_ip=src_ip, src_port=src_port, dst_port=dst_port)
        access_status = self.access_handler(src_ip=src_ip, dst_ip=dst_ip, proto=tcp_proto)

        # TODO 25.  Blocking TCP traffic
        if access_status:
            # pass # Comment me in TODO 26
            # Keep the body of the if statement only with the pass statement during TODO 25
            # Focus only in the else statement during TODO 25

            # TODO 26. Shortest path for TCP traffic
            shortest_path = self.path_handler(src_ip=src_ip, dst_ip=dst_ip, weight_func=self.load_balancer)
            # TODO 27. Routing for TCP traffic
            for index, link in enumerate(shortest_path):
                src_sw, dst_sw = link
                hop_dp = self.network.nodes[src_sw]['dp']
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=proto, ipv4_src=src_ip, ipv4_dst=dst_ip,in_port=dst_port)
                out_port = self.network.get_edge_data(src_sw, dst_sw)["src_port"]
                actions = [parser.OFPActionOutput(out_port)]
                self.logger.info(f"DP: {hop_dp.id}, Match: [TCP proto: {tcp_proto} src IP: {src_ip} dst IP: {dst_ip}], Out port: {out_port}")
                self.add_flow(dp=hop_dp, table=self.DEFAULT_TABLE, priority=self.HIGH_PRIORITY, match=match, actions=actions)

        #         # TODO 28. Forwarding initial ICMP packet
        #         if index == len(shortest_path) - 1:
        #             in_port = self.network.get_edge_data(XXX)["dst_port"]
        #             self.logger.info(f"Pkt-out DP: {hop_dp.id}, in-port: {in_port}, out-port: {out_port}")
        #             out = parser.OFPPacketOut(datapath=XXX, buffer_id=ev.msg.buffer_id, in_port=XXX, actions=XXX, data=ev.msg.data)
        #             hop_dp.send_msg(out)
        else:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ip_proto=proto, ipv4_src=src_ip, ipv4_dst=dst_ip, in_port=dst_port)
            actions = []
            self.logger.info(f"DP: {dp.id}, Match: [TCP proto: {tcp_proto} src IP: {src_ip} dst IP: {dst_ip}], Out port: [Block]")
            self.add_flow(dp=dp, table=self.DEFAULT_TABLE, priority=self.MEDIUM_PRIORITY, match=match, actions=actions, h_tout=self.HARD_TIMEOUT)

    def access_handler(self, src_ip, dst_ip, proto):
        if dst_ip in self.access_dict[src_ip]["hosts"] and proto in self.access_dict[src_ip]["protocols"]:
            self.logger.info(f"Access granted for Src IP: {src_ip}, Dst IP: {dst_ip} with Proto: {proto}")
            return True
        else:
            self.logger.info(f"Access denied for Src IP: {src_ip}, Dst IP: {dst_ip} with Proto: {proto}")
            return False

    def path_handler(self, src_ip, dst_ip, weight_func=None):
        if self.network.has_node(src_ip) and self.network.has_node(dst_ip):
            if weight_func is None:
                shortest_path = nx.shortest_path(self.network, source=src_ip, target=dst_ip)
            else:
                shortest_path = nx.shortest_path(self.network, source=src_ip, target=dst_ip, weight=weight_func)
            shortest_path = list(zip(shortest_path[1:-1], shortest_path[2:]))
            self.logger.info(f"SP h{src_ip} --> h{dst_ip}: {shortest_path}")
            return shortest_path
        else:
            self.logger.info(f"No SP found between h{src_ip} --> h{dst_ip}")
            return []

    def load_balancer(self, src, dst, data, **kwargs):
        edge = (src, dst)
        if edge in self.core_edges_list:
            cost = randint(*self.edge_cost_range)
            self.logger.info(f"Edge {edge} with cost {cost}")
            return cost
        return self.DEFAULT_EDGE_WEIGHT

    def tcp_proto_selector(self, src_ip, src_port, dst_port):
        if src_port in self.access_dict[src_ip]['protocols']:
            return src_port
        elif dst_port in self.access_dict[src_ip]['protocols']:
            return dst_port
        else:
            return None

    def poll_switch_load(self):
        while True:
            for node, data in self.network.nodes(data=True):
                if data["type"] == self.SWITCH_TYPE:
                    self.request_stats(data["dp"])
            # TODO 30. Retrieving packet stats
            # Change the sorting parameter to packets transmitted.
            util_list = self.utilization_sorter(sort_parameter=self.NUM_FLOWS_SORT)
            self.logger.info("Printing switch utilization information")
            for util_entry in util_list:
                self.logger.info(f"Switch s{util_entry['dpid']} tx. packets: {util_entry['tx_pkts']} num. flows {util_entry['num_flows']}")
            hub.sleep(self.MONITOR_PERIOD)

    def request_stats(self, datapath):
        self.logger.debug(f"Requesting stats from Switch s{datapath.id}")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # TODO 29. Retrieving flow stats
        # req = parser.OFPFlowStatsRequest(XXX)
        # datapath.send_msg(req)
        # TODO 30. Retrieving packet stats
        # req = parser.OFPPortStatsRequest(XXX, 0, ofproto.OFPP_ANY)
        # datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        # TODO 29. Retrieving flow stats
        # num_flows = XXX
        # # self.logger.info(f"s{dpid} num. flows: {num_flows}") # Commented to reduce output
        # self.network.nodes[XXX]["num_flows"] = XXX

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        # TODO 30. Retrieving packet stats
        # tx_pkts = 0
        # for port_stat in body:
        #     tx_pkts += port_stat.XXX
        # # self.logger.info(f"s{dpid} transmitted packets: {tx_pkts}") # commented to reduce output
        # self.network.nodes[XXX]["tx_pkts"] = XXX

    def utilization_sorter(self, sort_parameter="tx_pkts"):
        util_list = []
        for node, data in self.network.nodes(data=True):
            if data["type"] == self.SWITCH_TYPE:
                util_entry = {"dpid": node, "tx_pkts": data["tx_pkts"], "num_flows": data["num_flows"]}
                util_list.append(util_entry)
        return sorted(util_list, key=lambda dict_entry: dict_entry[sort_parameter], reverse=True)
