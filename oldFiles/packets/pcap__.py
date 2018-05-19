#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct

from pprint import pprint

from packets.packet import Packet
from utils.utils import isInternalIp


def addbl(ipblacklist, ssrc, sdst, mtype):
    if not isInternalIp(ssrc):
        if ssrc not in ipblacklist:
            ipblacklist[ssrc] = set()
        ipblacklist[ssrc].add(mtype)
    if not isInternalIp(sdst):
        if sdst not in ipblacklist:
            ipblacklist[sdst] = set()
        ipblacklist[sdst].add(mtype)


def removebl(ipblacklist, ssrc, sdst, mtype):
    if not isInternalIp(ssrc):
        if ssrc in ipblacklist and mtype in ipblacklist[ssrc]:
            ipblacklist[ssrc].remove(mtype)
            if len(ipblacklist[ssrc]) <= 0:
                ipblacklist.pop(ssrc)
    if not isInternalIp(sdst):
        if sdst in ipblacklist and mtype in ipblacklist[sdst]:
            ipblacklist[sdst].remove(mtype)
            if len(ipblacklist[sdst]) <= 0:
                ipblacklist.pop(sdst)


def splitByMaxTag(d):
    d = d.split(".")
    maxt = max(map(len, d))
    for ti in range(len(d)):
        if len(d[ti]) == maxt:
            return ".".join(d[ti+1:])


class Pcap(object):

    """Pcap file reader"""

    def __init__(self, filepath):
        super(Pcap, self).__init__()
        self.filepath = filepath
        fpcap = open(filepath, 'rb')
        packetNum = 0

        # pcap文件的数据包解析
        header = {}
        header['magic_number'] = fpcap.read(4)
        header['version_major'] = fpcap.read(2)
        header['version_minor'] = fpcap.read(2)
        header['thiszone'] = fpcap.read(4)
        header['sigfigs'] = fpcap.read(4)
        header['snaplen'] = fpcap.read(4)
        header['linktype'] = fpcap.read(4)
        self.header = header
        domainwindow = []
        dnsrespwindow = []
        ipblacklist = {}
        domainblacklist = []
        dnsShellList = []
        popWhiteList = set()

        packetCnt = 0

        while packetCnt < 5000:
            if packetCnt % 1000 == 0:
                print packetCnt
            header = fpcap.read(16)
            if len(header) < 16:
                break
            packetLen = struct.unpack('I', header[12:16])[0]
            try:
                packet = Packet(header, fpcap.read(packetLen), packetNum)
            except Exception as e:
                print(e)
            packetCnt += 1
            # print packet.layers
            lastlayer = packet.layers[-1]
            if packet.srcp == 53:
                dnsrespwindow.append(
                    lastlayer.resqdatahash + ";" + lastlayer.domains[0])
            if lastlayer.name == "DNS":
                domainwindow.extend(lastlayer.domains)
                for tmp in lastlayer.domains:
                    if max(map(len, tmp.split("."))) > 8:
                        if splitByMaxTag(tmp) in domainblacklist:
                            addbl(ipblacklist, packet.srcip,
                                  packet.dstip, "dns tunnel")
                        if splitByMaxTag(tmp) in dnsShellList:
                            addbl(ipblacklist, packet.srcip,
                                  packet.dstip, "dns shell tunnel")
            elif lastlayer.name == "SMTP":
                if lastlayer.type == "mal":
                    addbl(ipblacklist, packet.srcip,
                          packet.dstip, "pop tunnel")
            elif lastlayer.name == "POP":
                if lastlayer.type == "mal":
                    addbl(ipblacklist, packet.srcip,
                          packet.dstip, "pop tunnel")
            packetNum += 1
            if len(domainwindow) >= 100:
                # 最长标签大于8
                tmp = filter(lambda i: max(
                    map(len, i.split("."))) > 8, domainwindow)
                for i in range(len(tmp)):
                    tmp[i] = splitByMaxTag(tmp[i])
                domainlist = {}
                for t in tmp:
                    if t not in domainlist:
                        domainlist[t] = 0
                    else:
                        domainlist[t] += 1
                for d in domainlist:
                    if domainlist[d] > 40:
                        domainblacklist.append(d)

            if len(dnsrespwindow) >= 100:
                resplist = {}
                searchdict = {}
                for tmp in dnsrespwindow:
                    t = tmp.split(";")[0]
                    if t in resplist:
                        resplist[t] += 1
                    else:
                        searchdict[t] = tmp.split(";")[1]
                        resplist[t] = 1
                for tmp in resplist:
                    # print resplist[tmp]
                    if resplist[tmp] > 10:
                        dnsShellList.append(splitByMaxTag(searchdict[tmp]))
                dnsShellList = list(set(dnsShellList))
                # print "dnsShellList", dnsShellList
        pprint(ipblacklist)
        fpcap.close()
