#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket

from utils.utils import hexdump


class layer(object):

    """base layer"""

    def __init__(self, packet=""):
        self.packet = packet

    def pack(self):
        return self.packet

    def __str__(self):
        return self.pack()

    def __repr__(self):
        return "<%s>" % self.name

    @staticmethod
    def send(layers, port=0, device="eth0"):
        packet = ''.join([p.pack() for p in layers])
        if len(packet) < 60:
            packet += "\x00" * (60 - len(packet))
        hexdump(packet)
        return "=== TEST ==="
        rawSocket = socket.socket(
            socket.PF_PACKET, socket.SOCK_RAW, socket.htons(port)
        )
        rawSocket.bind((device, socket.htons(port)))
        rawSocket.send(packet)
        return rawSocket
    
    @property
    def name(self):
        return self.__class__.__name__