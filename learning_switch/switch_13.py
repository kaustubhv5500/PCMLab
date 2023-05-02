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
        # TODO 7. Create a sttructure to save the mac to port mappigs in every switch.
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
        self.switch_mac_port_map = None

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
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
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
        self.logger.info(
          "Packet in!. sw: s%s, port: %s, src mac: %s, dst mac: %s, ethertype: %s, length: %s"
          , None, None, None, None, ethertype, ev.msg.msg_len)

        # # TODO 8. Learn the source MAC address in this switch.
        # # Be carefull you don't forget previously learn stuff
        # if not XXX in self.switch_mac_port_map:
        #     # The first time you have to push the nested dict
        #     # self.switch_mac_port_map[XXX] = {XXX: XXX}
        # else:
        #     # self.switch_mac_port_map[XXX][XXX] = XXX
        # # You may wish to comment this for later when you are sure that the
        # # learnig process is working good
        # for mac_address, port_num in self.switch_mac_port_map[XXX].items():
        #     self.logger.info("src mac: %s, is at port: %s of sw: s%s",
        #         XXX, XXX, XXX)

        # # TODO 9. Check if the switch knows how to reach the destination MAC address
        # if XXX in self.switch_mac_port_map[XXX]:
        #     switch_out_port = self.switch_mac_port_map[XXX][XXX]
        # else:
        #     # If the switch does not know what to do
        #     # fallback to hub behavior
        #     switch_out_port = XXX
        # self.logger.info("dst mac: %s, is at port: %s of sw: s%s",
        #     XXX, XXX, XXX)

        # # TODO 10. Let's forward the packet,
        # # by telling the switch which port to use
        # actions = [parser.OFPActionOutput(XXX)]
        # out = parser.OFPPacketOut(datapath=XXX, buffer_id=ev.msg.buffer_id,
        #     in_port=XXX, actions=XXX, data=ev.msg.data)
        # datapath.send_msg(XXX)

        # # TODO 12. Adding flow rules.
        # # Only install the flow when the destination port is known
        # if switch_out_port != XXX:
        #     match = parser.OFPMatch(
        #         in_port=XXX, eth_dst=XXX, eth_src=XXX)
        #     self.logger.info("Installing flow in switch: s%s", XXX)
        #     self.logger.info("Match: pkts with in port: %s, src mac: %s and dst mac: %s -> Action: use out port: %s",
        #         XXX, XXX, XXX, XXX)
        #     self.add_flow(XXX, 1, XXX, XXX)
