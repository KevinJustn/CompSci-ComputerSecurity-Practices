#!/usr/bin/env python3

from scapy.all import *
def print_pkt(pkt):
    pkt.show()

# For privacy concerns, the "INTERFACE", "HOST", and "SUBNET" will not display the actual interface ID.

# The following packet sniffer sniffs ICMP packets:
pkt = sniff(iface='INTERFACE', filter='icmp', prn=print_pkt)

# The following packet sniffer sniffs TCP packets from a particular IP with destination port number 23:
pkt = sniff(iface='INTERFACE', filter='src host HOST and dst port 23', prn=print_pkt)

# The following packet sniffer sniffs from a particular subnet. 
pkt = sniff(iface='INTERFACE', filter='net SUBNET/16', prn=print_pkt)