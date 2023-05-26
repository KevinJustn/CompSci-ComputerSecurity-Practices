#!/usr/bin/env python3

# For privacy conerns, the destination port "DEST" will not be listed
from scapy.all import *
a = IP()
a.dst = 'DEST'
b = ICMP()

for i in range (1,5):
    a.ttl = i
    send(a/b)
