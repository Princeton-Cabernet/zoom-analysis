#!/usr/bin/env python

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *
import argparse
import sys

def pkt_handler(pkt):
    return(pkt.summary())

parser = argparse.ArgumentParser(description="Receive packets on a network interface and print their summaries.")
parser.add_argument('-i','--interface', help="Interface on which packets are received.", required=True)
args = vars(parser.parse_args())

sniff(iface=args["interface"], prn=pkt_handler)
