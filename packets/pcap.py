#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
import io

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
            return ".".join(d[ti + 1:])


class Pcap(object):
    """Pcap file reader"""

    def __init__(self, filepath):
        super(Pcap, self).__init__()
        self.filepath = filepath
        # io.DEFAULT_BUFFER_SIZE = 81920000
        fpcap = io.open(filepath, 'rb')
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

        resplist = {}
        searchdict = {}
        domainlist = {}

        # while packetNum < 5000:
        while True:
            # if packetNum % 1000 == 0: print packetNum
            header = fpcap.read(16)
            if len(header) < 16:
                break
            packetLen = struct.unpack('I', header[12:16])[0]
            try:
                packet = Packet(header, fpcap.read(packetLen), packetNum)
            except Exception as e:
                print(e)

            # print packet.layers
            lastlayer = packet.layers[-1]
            
            if packet.srcp == 53 and lastlayer.name == "DNS":
                # 判断是是否有返回域名信息，如果没有放弃处理
                if len(lastlayer.domains) == 0:
                    continue
                # 添加返回结果到结果池，根据当前情况判断该结果是否是恶意返回结果，如果是，则添加到黑名单
                dnsrespwindow.append(lastlayer.resqdatahash + ";" + lastlayer.domains[0])
                if len(dnsrespwindow) >= 100:
                    t = lastlayer.resqdatahash
                    if t in resplist:
                        resplist[t] += 1
                    else:
                        searchdict[t] = lastlayer.domains[0]
                        resplist[t] = 1
                    if resplist[t] > 10:
                        dnsShellList.append(splitByMaxTag(searchdict[t]))
                        # 去重
                        dnsShellList = list(set(dnsShellList))

            if lastlayer.name == "DNS":
                # 添加当前查询到域名池
                domainwindow.extend(lastlayer.domains)

                # =============
                # 根据域名长度判断是否为恶意域名，如果是，则添加到黑名单
                for domain in lastlayer.domains:
                    if max(map(len, domain.split("."))) > 8:
                        domain_maxtag = splitByMaxTag(domain)
                        if domain_maxtag not in domainlist:
                            domainlist[domain_maxtag] = 0
                        else:
                            domainlist[domain_maxtag] += 1
                        if domainlist[domain_maxtag] > 40:
                            domainblacklist.append(domain_maxtag)

                for tmp in lastlayer.domains:
                    if max(map(len, tmp.split("."))) > 8:
                        domain_maxtag = splitByMaxTag(tmp)
                        if domain_maxtag in domainblacklist:
                            addbl(ipblacklist, packet.srcip,
                                  packet.dstip, "dns tunnel")
                        if domain_maxtag in dnsShellList:
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

        pprint(ipblacklist)
        fpcap.close()
