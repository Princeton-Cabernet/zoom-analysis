#!/usr/bin/env python

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

SEND_IFACE = "veth1"

srv_pkt1 = Ether()/IP(src="10.0.2.24", dst="3.7.35.15")/UDP(sport=14922, dport=8801)

srv_pkt2 = Ether()/IP(src="140.180.5.5", dst="3.7.35.15")/TCP(sport=28329, dport=8801)

srv_pkt3 = Ether()/IP(src="3.7.35.15", dst="10.0.2.24")/TCP(sport=8801, dport=28329)

stun_pkt = Ether()/IP(src="140.180.9.9", dst="3.7.35.15")/UDP(sport=30300, dport=3478)

p2p_pkt1 = Ether()/IP(src="140.180.9.9", dst="3.50.33.3")/UDP(sport=30300, dport=29299)
p2p_pkt2 = Ether()/IP(src="3.50.33.3", dst="10.0.2.24")/UDP(sport=29299, dport=30300)

other_pkt1 = Ether()/IP(src="3.3.3.3", dst="4.4.4.4")/UDP(sport=34324, dport=64442)
other_pkt2 = Ether()/IP(src="3.5.8.33", dst="4.4.10.11")/UDP(sport=5444, dport=2232)
other_pkt3 = Ether()/IP(src="3.5.8.33", dst="4.4.10.11")/TCP(sport=5444, dport=2232)

sendp(srv_pkt1, iface=SEND_IFACE)
sendp(srv_pkt2, iface=SEND_IFACE)
sendp(srv_pkt3, iface=SEND_IFACE)

sendp(stun_pkt, iface=SEND_IFACE)

sendp(p2p_pkt1, iface=SEND_IFACE)
sendp(p2p_pkt2, iface=SEND_IFACE)

sendp(other_pkt1, iface=SEND_IFACE)
sendp(other_pkt2, iface=SEND_IFACE)
sendp(other_pkt3, iface=SEND_IFACE)
