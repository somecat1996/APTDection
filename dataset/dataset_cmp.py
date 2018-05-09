# -*- coding: utf-8 -*-


import io
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
        pathlib.Path(f'./cmp/tcppayload/{name}/{kind}/0').mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(f'./cmp/tcppayload/{name}/{kind}/1').mkdir(parents=True, exist_ok=True) # malicious
        pathlib.Path(f'./cmp/reassembly/{name}/{kind}/0').mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(f'./cmp/reassembly/{name}/{kind}/1').mkdir(parents=True, exist_ok=True) # malicious
        pathlib.Path(f'./cmp/httpv1body/{name}/{kind}/0').mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(f'./cmp/httpv1body/{name}/{kind}/1').mkdir(parents=True, exist_ok=True) # malicious

        for files in group.values():
            for file in files:
                pprint.pprint(file)
                label = int(file['malicious'] >= 1 or file['suspicious'] >= 1)
                dataset = file['filename'].replace('pcap', 'dat')
                loads(f'./stream/{name}/tmp/{file["filename"]}', f'{name}/{kind}/{label}/{dataset}')


def loads(fin, fout):
    fout1 = f'./cmp/tcppayload/{fout}'
    fout2 = f'./cmp/reassembly/{fout}'
    fout3 = f'./cmp/httpv1body/{fout}'
    print(f'Extracting file {fin} & dumping to ./cmp/*/{fout}')
    extractor = jspcap.Extractor(fin=fin, store=False, tcp=True, verbose=True, nofile=True, strict=True)
    for packet in extractor:
        tcp = packet[jspcap.TCP]
        dumps(fout1, tcp.raw or b'')
    #     if jspcap.HTTP in packet:
    #         http = packet[jspcap.HTTP]
    #         if http.body and 'text' in http.header['Content-Type']:
    #             dumps(fout, http.raw.body)
    for packet in extractor.reassembly.tcp:
        payload = packet['payload']
        report = jspcap.analyse(io.BytesIO(payload), len(payload))
        if report.protochain and jspcap.HTTP in report.protochain:
            dumps(fout2, report.info.raw.packet or b'')
            dumps(fout3, report.info.raw.body or b'')


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
