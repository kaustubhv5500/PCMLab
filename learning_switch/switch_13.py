from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class Switch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch13, self).__init__(*args, **kwargs)
        # TODO 7. Create a structure to save the mac to port mappigs in every switch.
        # A nested dictionary can be a convenient representation.
        # This is a example, the dictionary here should be empty.
        # Its contents will be pushed in the packet in handler.
        #  {
        #    swich_id:{
        #                mac_address:port_number,
        #                ...
        #             },
        #     ...
        #  }
        # Replace the None
        # Defining an empty dictionary to store the mac to port mappings for every switch individually
        self.switch_mac_port_map = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Installing rule in s%s", datapath.id)
        match = parser.OFPMatch()
        # TODO 5. Replace the default action with one that instructs
        # the switch to send unknown traffic to the controller.
        # Add an argument to avoid buffering packets in the switch
        # Replaced: actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        # Setting the actions to forward the packet to the controller and not to buffer
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.logger.info(type(ev))

        # Extracts switch info
        datapath = ev.msg.datapath
        switch_dpid = datapath.id
        switch_in_port = ev.msg.match['in_port']
        # Extracts OF handlers
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Extracts the packet
        pkt_in = packet.Packet(ev.msg.data)
        eth_header = pkt_in.get_protocols(ethernet.ethernet) [0]
        dst_mac = eth_header.dst
        src_mac = eth_header.src
        ethertype = eth_header.ethertype

        # TODO 6. Conplete the log message.
        # Replace the None with the respective variable.
        # Added the variables from the datapath, packet and header values
        self.logger.info(
          "Packet in!. sw: s%s, port: %s, src mac: %s, dst mac: %s, ethertype: %s, length: %s"
          , switch_dpid, switch_in_port, src_mac, dst_mac, ethertype, ev.msg.msg_len)

        # TODO 8. Learn the source MAC address in this switch.
        # Be carefull you don't forget previously learnt stuff
        if switch_dpid not in self.switch_mac_port_map:
            # The first time you have to push the nested dict
            # Set the switch id as an index to a nested dictionary which has the source mac
            # as the index and the input port as the key
            self.switch_mac_port_map[switch_dpid] = {src_mac: switch_in_port}
        else:
            self.switch_mac_port_map[switch_dpid][src_mac] = switch_in_port
        # You may wish to comment this for later when you are sure that the
        # learning process is working good
        # Log the mac address and the input port from the filled dictionary
        for mac_address, port_num in self.switch_mac_port_map[switch_dpid].items():
            self.logger.info("mac: %s, is at port: %s of sw: s%s",
                mac_address, port_num, switch_dpid)

        # TODO 9. Check if the switch knows how to reach the destination MAC address
        if dst_mac in self.switch_mac_port_map[switch_dpid]:
            switch_out_port = self.switch_mac_port_map[switch_dpid][dst_mac]
        else:
            # If the switch does not know what to do
            # fallback to hub behavior
            # If no info is known about the output port, FLOOD to all ports
            switch_out_port = ofproto.OFPP_FLOOD
        self.logger.info("dst mac: %s, is at port: %s of sw: s%s",
            dst_mac, switch_out_port, switch_dpid)

        # TODO 10. Let's forward the packet,
        # by telling the switch which port to use
        actions = [parser.OFPActionOutput(switch_out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ev.msg.buffer_id,
            in_port=switch_in_port, actions=actions, data=ev.msg.data)
        datapath.send_msg(out)

        # TODO 12. Adding flow rules.
        # Only install the flow when the destination port is known
        if switch_out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=switch_in_port, eth_dst=dst_mac, eth_src=src_mac)
            self.logger.info("Installing flow in switch: s%s", switch_dpid)
            self.logger.info("Match: pkts with in port: %s, src mac: %s and dst mac: %s -> Action: use out port: %s",
                switch_in_port, src_mac, dst_mac, switch_out_port)
            self.add_flow(datapath, 1, match, actions)
