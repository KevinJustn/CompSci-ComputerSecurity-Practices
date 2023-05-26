#!/usr/bin/env python3

# For privacy conerns, the host port "HOST" or interface "INTERFACE"will not be listed
from scapy.all import *

def spoof(packet):
    a = IP()
    a.dst = packet[IP].src
    b = packet[ICMP].id
    p = a/b
    send(p)

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='INTERFACE', filter='icmp and src host HOST', prn=print_pkt)