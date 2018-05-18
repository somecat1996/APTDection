# -*- coding: utf-8 -*-


import json
import jspcap
import os
import pathlib
import pprint
import sys


def make_dataset(name):
    with open(f'./dataset/{name}/stream.json', 'r') as file:
        labels = json.load(file)
    
    for kind, group in labels.items():
        pathlib.Path(f'./dataset/{name}/{kind}/0').mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(f'./dataset/{name}/{kind}/1').mkdir(parents=True, exist_ok=True) # malicious
        
        for files in group.values():
            for file in files:
                pprint.pprint(file)
                label = int(file['malicious'] >= 1 or file['suspicious'] >= 1)
                dataset = file['filename'].replace('pcap', 'dat')
                loads(f'./stream/{name}/tmp/{file["filename"]}', f"./dataset/{name}/{kind}/{label}/{dataset}")


def loads(fin, fout):
    print(f'Extracting file {fin} & dumping to {fout}')
    extractor = jspcap.Extractor(fin=fin, store=False, auto=False, nofile=True)
    for packet in extractor:
        tcp = packet[jspcap.TCP]
        dumps(fout, tcp.packet.payload or b'')
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
    # stream = make_steam(name)
    make_dataset(name)

main()
# if __name__ == '__mian__':
#     main()
