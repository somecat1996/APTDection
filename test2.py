from scapy.all import *
from chardet import detect
from scapy.layers import http

buffer = PcapReader("wanyong-80.pcap")
while True:
    packege = buffer.read_packet()
    if packege is None:
        break
    else:
        try:
            tmp = packege[TCP]
            if tmp.dport == 80 or tmp.sport == 80:
                tmp = tmp.payload
                print(tmp.Method)
                print(tmp.Host)
                if tmp.Referer != '':
                    print(tmp.Referer)
                else:
                    print('None')
                print()
        except:
            pass
