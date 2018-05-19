#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import struct

from layer.layer import layer


class VLAN(layer):

    IPv4 = 0x0800
    IPv6 = 0x86dd
    ARP = 0x0806

    def __init__(self):
        pass

    def pack(self):
        pass

    @staticmethod
    def unpack(packet):
        v = VLAN()
        data = struct.unpack('!BBH', packet)
        v.type = data[2]
        return v

    @property
    def stype(self):
        if self.type == self.IPv4:
            return "IPv4"
        elif self.type == self.ARP:
            return "ARP"
        elif self.type == self.IPv6:
            return "IPv6"
        return "unknown %d" % (self.type)

    def __repr__(self):
        return "<VLAN %s>" % (self.stype)

if __name__ == '__main__':
    pass
