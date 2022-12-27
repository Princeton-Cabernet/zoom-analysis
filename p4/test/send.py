#!/usr/bin/env python

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *
import argparse

SEND_IFACE = "veth1"

parser = argparse.ArgumentParser(description="Send packets to a network interface; designed to test our Zoom capture Tofino program.")
parser.add_argument('-i','--interface', help="Interface on which packets are sent.", default=SEND_IFACE, required=False)
parser.add_argument('-t','--type', help="Type of packet. Options: server, stun, p2p, other", required=True)
args = vars(parser.parse_args())

if args["type"] == "server":
    # Prepare packets
    srv_pkt1 = Ether()/IP(src="10.0.2.24", dst="3.7.35.15")/UDP(sport=14922, dport=8801)
    srv_pkt2 = Ether()/IP(src="140.180.5.5", dst="3.7.35.15")/TCP(sport=28329, dport=8801)
    srv_pkt3 = Ether()/IP(src="3.7.35.15", dst="10.0.2.24")/TCP(sport=8801, dport=28329)
    # Send packets
    sendp(srv_pkt1, iface=args["interface"])
    sendp(srv_pkt2, iface=args["interface"])
    sendp(srv_pkt3, iface=args["interface"])

elif args["type"] == "stun":
    # Prepare packet
    stun_pkt = Ether()/IP(src="140.180.9.9", dst="3.7.35.15")/UDP(sport=30300, dport=3478)
    # Send packet
    sendp(stun_pkt, iface=args["interface"])

# Send STUN packet before sending P2P packets; first P2P packet should be allowed, and the second one should be dropped.
elif args["type"] == "p2p":
    # Prepare packets
    p2p_pkt1 = Ether()/IP(src="140.180.9.9", dst="3.50.33.3")/UDP(sport=30300, dport=29299)
    p2p_pkt2 = Ether()/IP(src="3.50.33.3", dst="10.0.2.24")/UDP(sport=29299, dport=30300)
    # Send packets
    sendp(p2p_pkt1, iface=args["interface"])
    sendp(p2p_pkt2, iface=args["interface"])

elif args["type"] == "other":
    # Prepare packets
    other_pkt1 = Ether()/IP(src="3.3.3.3", dst="4.4.4.4")/UDP(sport=34324, dport=64442)
    other_pkt2 = Ether()/IP(src="3.5.8.33", dst="4.4.10.11")/UDP(sport=5444, dport=2232)
    other_pkt3 = Ether()/IP(src="3.5.8.33", dst="4.4.10.11")/TCP(sport=5444, dport=2232)
    # Send packets
    sendp(other_pkt1, iface=args["interface"])
    sendp(other_pkt2, iface=args["interface"])
    sendp(other_pkt3, iface=args["interface"])

else:
    print("INVALID ARGUMENT: Packet type not recognized.")
