/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** C O N S T & P A R S E R  ************************
*************************************************************************/


// TODO 2. Constants and headers declaration.
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;
const bit<9>  CTRL_PORT = 255;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header arp_t {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8>  hw_add_len;
    bit<8>  proto_add_len;
    bit<16> opcode;
    bit<48> sender_hw_addr;
    bit<32> sender_proto_addr;
    bit<48> target_hw_addr;
    bit<32> target_proto_addr;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}


// TODO 10. Defining packet-in functionality.
// Packet-in header, prepended to packets sent to the controller
@controller_header("packet_in")
header packet_in_t {
  bit<16> ingress_port;
}


//TODO 15. Defining packet-out functionality.
// Packet-out header, prepended to packets received from the controller
@controller_header("packet_out")
header packet_out_t {
    bit<16> egress_port;
}


struct metadata {

    // TODO 6. Table definition.
    bit<32> dst_ipv4;
    bit<32> src_ipv4;

}

struct headers {
    // TODO 10. Defining packet-in functionality.
    packet_in_t  packet_in;

    // TODO 15. Defining packet-out functionality.
    packet_out_t packet_out;

    // TODO 3. Headers instantiation.
    ethernet_t ethernet;
    arp_t arp;
    ipv4_t ipv4;

}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            // TODO 15. Defining packet-out functionality.
            CTRL_PORT: parse_packet_out;
            // Change the default transition after TODO 4
            // TODO 4: Set default transition as parse_ethernet
            default: parse_ethernet;
        }
    }

    // TODO 15. Defining packet-out functionality.
    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }


    // TODO 4. Parser definition.
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // TODO 5. Actions definition.
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    // TODO 10. Defining packet-in functionality.
    action send_to_ctrl() {
        hdr.packet_in.setValid();
        standard_metadata.egress_spec = CTRL_PORT;
        hdr.packet_in.ingress_port = (bit<16>) standard_metadata.ingress_port;
    }


    // TODO 6. Table definition.
    table ipv4_exact {
        key = {
            // Define the match fields in the struct metadata
            meta.src_ipv4: exact;
            meta.dst_ipv4: exact;
        }
        actions = {
            ipv4_forward;
            // TODO 10. Defining packet-in functionality.
            // Only include the action send_to_ctrl after TODO 10
            send_to_ctrl;
            drop;
            NoAction;
        }
        size = 1024;
        // default_action = drop();
        // TODO 10. Defining packet-in functionality.
        // Update the default action to send_to_ctrl after TODO 10
        default_action = send_to_ctrl();
    }


    apply {
        // TODO 15. Defining packet-out functionality.
        if (hdr.packet_out.isValid()) {
            standard_metadata.egress_spec = (bit<9>) hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
        }

        // TODO 7. Using the table.
        // Change if to else if after TODO 15
        else if (hdr.arp.isValid()) {
            meta.src_ipv4 = hdr.arp.sender_proto_addr;
            meta.dst_ipv4 = hdr.arp.target_proto_addr;
            ipv4_exact.apply();
        } else if (hdr.ipv4.isValid()) {
            meta.src_ipv4 = hdr.ipv4.srcAddr;
            meta.dst_ipv4 = hdr.ipv4.dstAddr;
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            ipv4_exact.apply();
        } else {
            drop();
        }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {

       // TODO 3. Headers instantiation.
        update_checksum(
            hdr.ipv4.isValid(),{
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

        // TODO 10. Defining packet-in functionality.
        packet.emit(hdr.packet_in);

        // TODO 8.  Deparsing packets.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);

    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
