#!/usr/bin/env python

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

RECEIVE_IFACE = "veth3"

def pkt_handler(pkt):
    return(pkt.summary())


sniff(iface=RECEIVE_IFACE, prn=pkt_handler)
