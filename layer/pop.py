#!/usr/bin/env python
# -*- coding: utf-8 -*-

import string
import socket
import struct

from layer.layer import layer


class POP(layer):

    cmds = ["auth", "capa", "dele",
            "user", "pass", "stat", "list",
            "uidl", "retr", "quit", "top",
            "+ok", "noop", "-err"]
    codes = ["221", "220", "250", "334", "354", "550"]

    def __init__(self):
        self.errorno = 0
        self.type = ""

    def pack(self):
        pass

    @classmethod
    def unpack(cls, packet):
        pop = cls()
        if len(packet) < 1:
            pop.type = "null"
            return pop
        if len(packet) > 100:
            pop.type = "bigdata"
            return pop
        if packet == "\x00" * 6:
            return pop
        if "_NextPart_" in packet:
            pop.type = "data"
            return pop
        p = packet.split("\r\n")
        fp = p[0].split(" ")
        if fp[0] in cls.codes:
            pop.type = "ret"
            pop.code = fp[0]
            if len(p) > 1:
                pop.msg = fp[1:]
        elif fp[0].lower() in cls.cmds:
            pop.type = "req"
            pop.cmd = fp[0]
            if len(p) > 1:
                pop.args = fp[1:]
        else:
            cnt = len(filter(lambda i: i not in string.printable, packet))
            if cnt > 0.8 * len(packet):
                pop.type = "mal"
        return pop

if __name__ == '__main__':
    pass
