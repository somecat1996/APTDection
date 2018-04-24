from scapy.all import *
import csv
from .VirusTotal import *
import os


def write(payload, label, path):
    if len(payload) > 28 ** 2:
        payload = payload[:28 ** 2]
    # else:
    #     payload += (28 ** 2 - len(payload)) * b"\x00"
    writefile = open(path, 'a', newline='')
    csv_writer = csv.writer(writefile, dialect='excel')
    csv_writer.writerow([payload, label])


def read(path):
    file = sniff(offline=path)
    payload = ''
    for packet in file:
            try:
                payload += packet[payload]
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
            payload = read(path + file)
            packets = sniff(offline=path + file)
            label = 0
            for packet in packets:
                try:
                    if self.LabelByMyself(packet):
                        label = 1
                except:
                    print("connect failed")
                time.sleep(30)
            write(payload, label, outpath + file + "Single.csv")

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

