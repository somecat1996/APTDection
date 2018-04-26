# -*- coding: utf-8 -*-


# from scapy.all import *
from .VirusTotal import *
import os
import jspcap


"""
>>> from APTDection.FileReader.FileCombination import *
>>> a = FileCombination()
>>> a.SingleFolderOperator("./pkt2flow/stream/user_click2/pkt2flow.out/tcp_nosyn/", "./files/")
"""


def write(payload, path):
    if len(payload) > 28 ** 2:
        payload = payload[:28 ** 2]
    # else:
    #     payload += (28 ** 2 - len(payload)) * b"\x00"
    writefile = open(path, 'wb')
    writefile.write(payload)
    writefile.close()


def read(path):
    # file = sniff(offline=path)
    file = jspcap.Extractor(fin=path, nofile=True, auto=False, store=False)
    payload = b''
    for packet in file:
        # try:
        #     payload += packet[TCP].load
        # except:
        #     pass
        if jspcap.HTTP in packet:
            payload += packet[jspcap.HTTP].raw.body
    return payload


class FileCombination:
    def __init__(self):
        self.PcBrowserFileList = []
        self.PcAppFileList = []
        self.PhoneBrowserFileList = []
        self.PhoneAppFileList = []
        self.OutputPath = None
        self.scanner = virustotal()

    def SingleFolderOperator(self, path, outpath):
        files = [x for x in os.listdir(path)]
        alreadyfiles = [x for x in os.listdir(outpath)]
        print(files)
        for file in files:
            if file + "-Single-1" in alreadyfiles or file + "-Single-0" in alreadyfiles:
                print(file + "already exists")
                continue
            print("open " + file)
            already = []
            # packets = sniff(offline=path + file)
            packets = jspcap.Extractor(fin=path + file, nofile=False).frame
            payload = b''
            for packet in packets:
                # try:
                #     payload += packet[TCP].load
                # except:
                #     pass
                if jspcap.HTTP in packet:
                    payload += packet[jspcap.HTTP].raw.body
            label = 0
            for packet in packets:
                # try:
                #     src = "http://" + packet[IP].src
                #     dst = "http://" + packet[IP].dst
                # except:
                #     continue
                if jspcap.IP in packet:
                    src = 'http://' + packet[jspcap.IP].src
                    dst = 'http://' + packet[jspcap.IP].dst
                if src not in already:
                    fail = 1
                    while fail:
                        fail = 0
                        try:
                            src_label = self.scanner.label(src)
                        except:
                            print("连接失败，等待60秒重连")
                            fail = 1
                            time.sleep(60)
                    if src_label:
                        print("IP address " + src + " is malicious")
                        label = 1
                        already.append(src)
                    else:
                        already.append(src)
                    if dst not in already:
                        fail = 1
                        while fail:
                            fail = 0
                            try:
                                dst_label = self.scanner.label(dst)
                            except:
                                print("连接失败，等待60秒重连")
                                fail = 1
                                time.sleep(60)
                        if dst_label:
                            print("IP address " + dst + " is malicious")
                            label = 1
                            already.append(dst)
                        else:
                            already.append(dst)
            print(label, file)
            write(payload, outpath + file + "-Single-" + str(label))

    def ManagerReader(self, ManagerList):
        for i in ManagerList:
            if i[1] == 1:
                self.PcBrowserFileList.append((i[0], i[2]))
            if i[1] == 2:
                self.PcAppFileList.append((i[0], i[2]))
            if i[1] == 3:
                self.PhoneBrowserFileList.append((i[0], i[2]))
            if i[1] == 4:
                self.PhoneAppFileList.append((i[0], i[2]))

    def Combination(self, path):
        for item in self.PcBrowserFileList:
            payload = read(item[0])
            write(payload, item[1], path + "PcBrowser.csv")
        for item in self.PcAppFileList:
            payload = read(item[0])
            write(payload, item[1], path + "PcApp.csv")
        for item in self.PhoneBrowserFileList:
            payload = read(item[0])
            write(payload, item[1], path + "PhoneBrowser.csv")
        for item in self.PhoneAppFileList:
            payload = read(item[0])
            write(payload, item[1], path + "PhoneApp.csv")

    def LabelByMyself(self, packet):
        try:
            src = "http://" + packet[IP].src
            dst = "http://" + packet[IP].dst
        except:
            return 0
        lable = 0
        if self.scanner.label(src):
            print("IP address %s is malicious") % src
            lable = 1
        if self.scanner.label(dst):
            print("IP address %s is malicious") % dst
            lable = 1
        return lable
