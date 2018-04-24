from scapy.all import *
import csv
from .VirusTotal import *
import os


def write(payload, label, path):
    if len(payload) > 28 ** 2:
        payload = payload[:28 ** 2]
    # else:
    #     payload += (28 ** 2 - len(payload)) * b"\x00"
    writefile = open(path, 'a')
    csv_writer = csv.writer(writefile, dialect='excel')
    csv_writer.writerow([payload, label])
    writefile.close()


def read(path):
    file = sniff(offline=path)
    payload = b''
    for packet in file:
        try:
            payload += packet[TCP].load
        except:
            pass
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
        print(files)
        for file in files:
            already = []
            packets = sniff(offline=path + file)
            payload = b''
            for packet in packets:
                try:
                    payload += packet[TCP].load
                except:
                    pass
            label = 0
            for packet in packets:
                try:
                    src = "http://" + packet[IP].src
                    dst = "http://" + packet[IP].dst
                except:
                    continue
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
                                src_label = self.scanner.label(dst)
                            except:
                                print("连接失败，等待60秒重连")
                                fail = 1
                                time.sleep(60)
                        if src_label:
                            print("IP address " + dst + " is malicious")
                            label = 1
                            already.append(dst)
                        else:
                            already.append(dst)
            write(payload, label, outpath + file + "-Single.csv")

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

