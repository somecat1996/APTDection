from scapy.all import *
import csv


def write(payload, lable, path):
    writefile = open(path, 'a', newline='')
    csv_writer = csv.writer(writefile, dialect='excel')
    csv_writer.writerow([payload, lable])


def read(path):
    file = sniff(offine=path)
    payload = ''
    for packet in file:
            try:
                payload += packet.payload
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
