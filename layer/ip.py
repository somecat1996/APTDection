#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
IP Packet format

    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver = 4|IHL = 8|Type of Service|       Total Length = 576      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Identification = 111    |Flg=0|     Fragment Offset = 0 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Time = 123  |  Protocol = 6 |       Header Checksum         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        source address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      destination address                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Opt. Code = x | Opt.  Len.= 3 | option value  | Opt. Code = x |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Opt. Len. = 4 |           option value        | Opt. Code = 1 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Opt. Code = y | Opt. Len. = 3 |  option value | Opt. Code = 0 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   \                                                               \
   \                                                               \
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

import socket
import struct

from random import randint

from utils.utils import checksum
from layer.layer import layer


class IP(layer):

    protocolDict = {
        1: "ICMP",
        2: "IGMP",
        4: "encapsulation",
        6: "TCP",
        17: "UDP",
        45: "IDRP",
        46: "RSVP",
        47: "GRE",
        54: "NHRP",
        88: "IGRP",
        89: "OSPF",
    }

    class Protocol:
        ICMP = 1
        IGMP = 2
        encapsulation = 4
        TCP = 6
        UDP = 17
        IDRP = 45
        RSVP = 46
        GRE = 47
        NHRP = 54
        IGRP = 88
        OSPF = 89

    def __init__(self, ip=None):

        if ip is None:
            return
        self.version = ip['version']
        self.ihl = ip['ihl']
        self.tos = ip['tos']
        self.tl = int(ip['tolen'])  # total ength
        self.id = ip['id']
        self.flags = int(ip['flags'])
        self.offset = ip['offset']
        self.ttl = ip['ttl']
        self.protocol = int(ip['proto'])
        self.checksum = 0
        self.source = socket.inet_aton(ip['src'])
        self.destination = socket.inet_aton(ip['dst'])
        if 'options' in ip:
            self.options = ip['options'].decode("hex")

    def pack(self):
        ver_ihl = (self.version << 4) + self.ihl
        flags_offset = (self.flags << 13) + self.offset
        ipHeader = struct.pack("!BBHHHBBH4s4s",
                               ver_ihl,
                               self.tos,
                               self.tl,
                               self.id,
                               flags_offset,
                               self.ttl,
                               self.protocol,
                               self.checksum,
                               self.source,
                               self.destination)
        self.checksum = checksum(ipHeader + self.options)
        ipHeader = struct.pack("!BBHHHBBH4s4s",
                               ver_ihl,
                               self.tos,
                               self.tl,
                               self.id,
                               flags_offset,
                               self.ttl,
                               self.protocol,
                               socket.htons(self.checksum),
                               self.source,
                               self.destination)
        ipHeader += self.options
        if len(ipHeader) % 4 != 0:
            ipHeader += '\x00' * (4-(len(ipHeader) % 4))
        return ipHeader

    @staticmethod
    def unpack(packet):
        ip = IP()
        ip.ihl = 20
        iph = struct.unpack("!BBHHHBBH4s4s", packet[:ip.ihl])
        ip.version = (iph[0] - ip.ihl) >> 4
        ip.tos = iph[1]
        ip.tl = iph[2]
        ip.id = iph[3]
        ip.flags = iph[4] >> 13
        ip.offset = iph[4] & 0x1FFF
        ip.ttl = iph[5]
        ip.protocol = iph[6]
        ip.checksum = iph[7]
        ip.source = iph[8]
        ip.destination = iph[9]
        ip.options = ""
        return ip

    @property
    def sprotocol(self):
        return self.protocolDict.get(self.protocol, "unknown")
    
    @property
    def ssrc(self):
        return socket.inet_ntoa(self.source)
    
    @property
    def sdst(self):
        return socket.inet_ntoa(self.destination)

    def __repr__(self):
        return "<IP %s -> %s>" % (
            self.ssrc, self.sdst
        )

if __name__ == '__main__':

    ipConfig = {}
    ipConfig["version"] = 4  # version 4 or 6
    ipConfig["ihl"] = 20  # header length
    ipConfig["tos"] = 0  # type of service
    ipConfig["tolen"] = 572
    ipConfig['payload'] = ''
    ipConfig['id'] = randint(0, 65535)
    ipConfig['flags'] = 2  # Don't fragment
    # three bit
    # bit 0 => reserved, must be zero
    # bit 1 => may fragment, 1 = don't fragment
    # bit 2 => last fragment, 1 = more fragment
    ipConfig['offset'] = 0
    ipConfig['ttl'] = 64  # 8 < ttl < 255
    ipConfig['proto'] = 6
    ipConfig['checksum'] = 0  # will be filled by kernel
    ipConfig['src'] = '127.0.0.1'
    ipConfig['dst'] = '127.0.0.1'
    ipConfig['options'] = 'aa'
    ip = IP(ipConfig)
    packet = ip.pack()
    print(packet.encode('hex'))
    print(ip.unpack(packet).pack().encode('hex'))
