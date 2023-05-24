
from scapy.all import Ether, IP, UDP, send, ICMP, Raw
from time import sleep, localtime, strftime
from sys import argv

telemetry_port = 33333

def main(pkt_per_second):

    # icmp_packet = IP(dst="10.0.0.2", ttl=20)/ICMP()
    # send(icmp_packet, iface="eth0")

    pkt_base = IP(dst='10.0.0.2') / UDP(sport=44444, dport=telemetry_port)
    pkt_base.show()

    while(True):
        pkt = pkt_base / Raw(strftime('%H:%M:%S', localtime()))
        print(pkt.summary())
        send(pkt, iface="eth0")
        sleep(1/pkt_per_second)

if __name__ == '__main__':
    pkt_per_second = 1
    if len(argv) >= 2:
        pkt_per_second = int(argv[1])
    print(f"Rate: {pkt_per_second} pakte(s) per second")
    main(pkt_per_second)
