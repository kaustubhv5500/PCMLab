#include <core.p4>
#include <v1model.p4>

// TODO 6a Header definitions
// Standard Ethernet header
header ethernet_t {
   bit<48> dstAddr;
   bit<48> srcAddr;
   bit<16> etherType;
 }

 // Standard IPv4 header
header ipv4_t {
   bit<4> version;
   bit<4> ihl;
   bit<8> diffserv;
   bit<16> totalLen;
   bit<16> identification;
   bit<3> flags;
   bit<13> fragOffset;
   bit<8> ttl;
   bit<8> protocol;
   bit<16> hdrChecksum;
   bit<32> srcAddr;
   bit<32> dstAddr;
 }

// Standard TCP header
header tcp_t {
  bit<16> srcPort;
  bit<16> dstPort;
  bit<32> seqNo;
  bit<32> ackNo;
  bit<4> dataOffset;
  bit<4> res;
  bit<8> flags;
  bit<16> window;
  bit<16> checksum;
  bit<16> urgentPtr;
 }

// Standard UDP header
header udp_t {
  bit<16> srcPort;
  bit<16> dstPort;
  bit<16> length;
  bit<16> checksum;
}

// INT header
// Size in bytes of INT header: 21
header telemetry_t {
  bit<48> ingress_global_timestamp;
  bit<48> egress_global_timestamp;
  bit<19> enq_qdepth;
  bit<19> deq_qdepth;
  bit<32> deq_timedelta;
  bit<2> padding;
}

struct metadata {}
struct headers {
    // TODO 6b Header ordering
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    telemetry_t telemetry;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    // TODO 7 Parser definition
    // state start { transition accept; }
    state start {
      packet.extract(hdr.ethernet);
      transition select(hdr.ethernet.etherType) {
        0x0800: parse_ipv4;
        default: accept;
      }
    }

    state parse_ipv4 {
      packet.extract(hdr.ipv4);
      transition select(hdr.ipv4.protocol) {
        0x06: parse_tcp;
        0x11: parse_udp;
        default: accept;
      }
    }

    state parse_tcp {
      packet.extract(hdr.tcp);
      transition accept;
    }

    state parse_udp {
      packet.extract(hdr.udp);
      transition accept;
    }
  }

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // TODO 4a. Table and actions definition
    action set_egress_spec(bit<9> port) {
      standard_metadata.egress_spec = port;
    }

    action drop() {
      mark_to_drop(standard_metadata);
    }

    table forward {
      key = { standard_metadata.ingress_port: exact; }
      actions = {
                  set_egress_spec;
                  drop;
                }
      size = 1024;
      default_action = drop();
    }

    apply {
        // TODO 1. Wiring ports 1 and 2
        /* if (standard_metadata.ingress_port == 1) {
          standard_metadata.egress_spec = 2;
        }
        else if (standard_metadata.ingress_port == 2) {
          standard_metadata.egress_spec = 1;
        } */

        // TODO 4b. Apply the table
        // Do not forget to comment the code of TODO 1
        forward.apply();
      }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // TODO 9. Populating in-network telemetry header
        if (hdr.udp.isValid()) {
          if (hdr.udp.dstPort == 33333) {
            // Enable telemetry header and populate fields
            hdr.telemetry.setValid();
            hdr.telemetry.ingress_global_timestamp = standard_metadata.ingress_global_timestamp;
            hdr.telemetry.egress_global_timestamp = standard_metadata.egress_global_timestamp;
            hdr.telemetry.enq_qdepth = standard_metadata.enq_qdepth;
            hdr.telemetry.deq_qdepth = standard_metadata.deq_qdepth;
            hdr.telemetry.deq_timedelta = standard_metadata.deq_timedelta;
            // Correct length fields adding size of INT header
            hdr.udp.length = hdr.udp.length + 21;
            hdr.ipv4.totalLen = hdr.ipv4.totalLen + hdr.udp.length;
          }
        }
      }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // TODO 8. Deparser definition
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.telemetry);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
