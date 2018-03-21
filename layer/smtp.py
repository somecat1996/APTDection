#!/usr/bin/env python
# -*- coding: utf-8 -*-

import string
import socket
import struct

from layer.layer import layer
from utils.utils import entropy


class SMTPParseError(Exception):
    pass


class SMTP(layer):

    cmds = ["auth", "ehlo", "mail", "rcrt", "helo",
            "quit", "rset", "data", "bdat", "user",
            "pass", "list", "uidl", "capa"]
    codes = ["221", "220", "250", "334", "354", "550"]

    def __init__(self):
        self.errorno = 0
        self.type = ""

    def pack(self):
        pass

    @classmethod
    def unpack(cls, packet):
        s = SMTP()
        if len(packet) < 1:
            s.type = "null"
            return s
        if len(packet) > 100:
            s.type = "bigdata"
            s.data = packet
            return s
        p = packet.split("\r\n")
        fp = p[0].split(" ")
        if fp[0] in cls.codes:
            s.type = "ret"
            s.code = fp[0]
            if len(p) > 1:
                s.msg = fp[1:]
        elif fp[0].lower() in cls.cmds:
            s.type = "req"
            s.cmd = fp[0]
            if len(p) > 1:
                s.args = fp[1:]
        return s

if __name__ == '__main__':
    pass
