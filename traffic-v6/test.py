from packets.pcap import Pcap
from utils.pcap import parsePcap
import sys

if __name__ == '__main__':
    if len(sys.argv) <> 2: 
        print 'usage:python test filepath/filename'
        exit(1)
    Pcap(sys.argv[1])