#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import struct

from utils.utils import checksum
from layer import layer


class UDP(layer):

    def __init__(self, udp=None):
        if udp is None:
            return
        self.src = udp['srcp']
        self.dst = udp['dstp']
        self.payload = udp['payload']
        self.checksum = 0
        self.length = 8  # UDP Header length

    def pack(self):
        length = self.length + len(self.payload)
        pseudoHeader = struct.pack('!HHBBH',
                                   self.src,
                                   self.dst, 0,
                                   socket.IPPROTO_UDP,
                                   self.length)
        self.checksum = checksum(pseudoHeader)
        packet = struct.pack('!HHHH', self.src, self.dst,
                             length, self.checksum)
        return packet + self.payload.encode('hex')

    @staticmethod
    def unpack(data):
        data = struct.unpack("!HHHH", data)
        udp = UDP()
        udp.src = data[0]
        udp.dst = data[1]
        udp.length = data[2]
        udp.checksum = data[3]
        return udp

    def __repr__(self):
        return "<UDP %s -> %s>" % (
            self.src,
            self.dst
        )

if __name__ == '__main__':
    udpConfig = {}
    udpConfig['srcp'] = 13987
    udpConfig['dstp'] = 1234
    udpConfig['payload'] = ''
    udp = UDP(udpConfig)
    print udp.pack()
