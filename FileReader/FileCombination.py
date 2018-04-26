from scapy.all import *
from .DataLabeler import *
import os

'''
>>> from APTDection.FileReader.FileCombination import *
>>> a = FileCombination()
>>> a.SingleFolderOperator("./pkt2flow/stream/user_click2/pkt2flow.out/tcp_nosyn/", "./files/")
'''

def write(payload, path):
    if len(payload) > 1024:
        payload = payload[:1024]
    # else:
    #     payload += (28 ** 2 - len(payload)) * b"\x00"
    writefile = open(path, 'wb')
    writefile.write(payload)
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
        self.scanner = Datalabler()
        self.scanner.setThreadNum(20)

    def SingleFolderOperator(self, path, outpath):
        files = [x for x in os.listdir(path)]
        alreadyfiles = [x for x in os.listdir(outpath)]
        print(files)
        for file in files:
            if file + "-Single-1" in alreadyfiles or file + "-Single-0" in alreadyfiles:
                print(file + "already exists")
                continue
            print("open " + file)
            packets = sniff(offline=path + file)
            url = set()
            payload = b''
            for packet in packets:
                try:
                    payload += packet[TCP].load
                    url.add("http://" + packet[IP].src)
                    url.add("http://" + packet[IP].dst)
                except:
                    pass
            label = 0
            results = self.scanner.lable(url)
            for i in results:
                if i['malicous'] > 2:
                    label = 1
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
