# from packets.pcap import Pcap
from scapy.all import *

f = sniff(offline="test2.pcap")
for packet in f:
    print(packet.payload)

# Pcap("wanyong-80.pcap")