# -*- coding: utf-8 -*-


import json
import jspcap
import os
import pathlib
import pprint
import shutil
import sys

from webgraphic import *
from StreamManager3 import *


FLOW_DICT = {
    'Browser_PC' : lambda stream: stream.GetBrowserGroup_PC(),
    'Backgroud_PC' : lambda stream: stream.GetBackgroudGroup_PC(),
    'Browser_Phone' : lambda stream: stream.GetBrowserGroup_Phone(),
    'Backgroud_Phone' : lambda stream: stream.GetBackgroudGroup_Phone(),
    'Suspicious' : lambda stream: stream.GetSuspicious(),
}


def make_steam(name):
    pathlib.Path(f'./stream/{name}').mkdir(parents=True, exist_ok=True)
    # shutil.copy(f'{name}.pcap', f'./stream/{name}/{name}.pcap')

    builder = webgraphic()
    builder.read_in(f'./stream/{name}/{name}.pcap')
    IPS = builder.GetIPS()
    print('\n', IPS, '\n')

    stream = StreamManager(f'{name}.pcap')
    stream.generate()
    stream.classify(IPS)
    stream.LableAndGroup()

    # typeone = stream.GetBrowserGroup_PC()
    # typetwo = stream.GetBackgroudGroup_PC()
    # typethree = stream.GetBrowserGroup_Phone()
    # typefour = stream.GetBackgroudGroup_Phone()
    # typefive = stream.GetSuspicious()

    return stream


def make_record(name, stream):
    JSON = dict()
    for kind, group in FLOW_DICT.items():
        pathlib.Path(f'./dataset/{name}/{kind}/0').mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(f'./dataset/{name}/{kind}/1').mkdir(parents=True, exist_ok=True) # malicious
        JSON[kind] = group(stream)

    with open(f'./dataset/{name}/stream.json', 'w') as file:
        json.dump(JSON, file)


def make_dataset(name, stream):
    make_record(name, stream)
    for kind, group in FLOW_DICT.items():
        for files in group(stream).values():
            for file in files:
                pprint.pprint(file)
                label = int(file['malicious'] >= 1 or file['suspicious'] >= 1)
                dataset = file['filename'].replace('pcap', 'dat')
                loads(f'./stream/{name}/tmp/{file["filename"]}', f"./dataset/{name}/{kind}/{label}/{dataset}")


def loads(fin, fout):
    print(f'Extracting file {fin} & dumping to {fout}')
    extractor = jspcap.Extractor(fin=fin, store=False, verbose=True, auto=False, nofile=True)
    for packet in extractor:
        tcp = packet[jspcap.TCP]
        dumps(fout, tcp.raw or b'')
    #     if jspcap.HTTP in packet:
    #         http = packet[jspcap.HTTP]
    #         if http.body and 'text' in http.header['Content-Type']:
    #             dumps(fout, http.raw.body)
    print()


def dumps(name, byte):
    # print(f'Writing to file {name}')
    with open(name, 'ab') as file:
        file.write(byte)

def main():
    name = os.path.splitext(sys.argv[1])[0]
    # name = input('File name: ')
    # name = os.path.splitext(name)[0]
    # print(name)
    stream = make_steam(name)
    make_dataset(name, stream)

main()
# if __name__ == '__mian__':
#     main()
