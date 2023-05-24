from scapy.all import sniff, BitField, UDP, bind_layers, Packet, Ether, IP, TCP

telemetry_port = 33333
switch_timedelta = []
enq_qdepth = []
deq_qdepth = []
deq_timedelta = []
n_samples = 100

class telemetry_t(Packet):
    name = 'Telemetry header'
    fields_desc = [BitField(name='ingress_global_timestamp', default=0, size=48),
                   BitField(name='egress_global_timestamp', default=0, size=48),
                   BitField(name='enq_qdepth', default=0, size=19),
                   BitField(name='deq_qdepth', default=0, size=19),
                   BitField(name='deq_timedelta', default=0, size=32),
                   BitField(name='padding', default=0, size=2),]

def process_pkt(pkt):
    if telemetry_t in pkt:
        pkt.show()
        if len(switch_timedelta) <= n_samples:
            # TODO 11.  Store 100 samples of in_network telemetry data
            # Use the global variables to persist your
            # data accross invocations to this funciton
            # It is easier to copy the output of this script if you run it
            # directly on mininet (H2 python3 receive_pkt.py)
            switch_timedelta.append(pkt["Telemetry header"].egress_global_timestamp - pkt["Telemetry header"].ingress_global_timestamp)
            enq_qdepth.append(pkt["Telemetry header"].enq_qdepth)
            deq_qdepth.append(pkt["Telemetry header"].deq_qdepth)
            deq_timedelta.append(pkt["Telemetry header"].deq_timedelta)
        else:
            print(switch_timedelta)
            print(enq_qdepth)
            print(deq_qdepth)
            print(deq_timedelta)
    else:
        print(pkt.summary())


def main():
    bind_layers(UDP, telemetry_t, dport=telemetry_port)
    sniff(iface="eth0", prn=process_pkt)


if __name__ == '__main__':
    main()
