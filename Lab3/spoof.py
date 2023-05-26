#!/usr/bin/env python3

# For privacy conerns, the destination port "DEST" will not be listed
from scapy.all import *
a = IP()
a.dst = 'DEST'
b = ICMP()
p = a/b
send(p)