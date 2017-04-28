#!/usr/bin/python
import sys
from scapy.all import *
pkt=RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="aa:aa:aa:aa:aa:aa",addr3="aa:aa:aa:aa:aa:aa")/Dot11Beacon()/Dot11Elt(ID=36,info="demodemodemodemodemodemo")
sendp(pkt, iface="wlan0mon", count=100000)
