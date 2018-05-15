# -*- coding: utf-8 -*-


import io
import json
import jspcap
import os
import pathlib
import pprint
import sys


def make_dataset():
    with open(f'./stream.json', 'r') as file:
        labels = json.load(file)

    for kind, group in labels.items():
        pathlib.Path(f'./cmp/tcppayload/{kind}/0').mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(f'./cmp/tcppayload/{kind}/1').mkdir(parents=True, exist_ok=True) # malicious
        pathlib.Path(f'./cmp/reassembly/{kind}/0').mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(f'./cmp/reassembly/{kind}/1').mkdir(parents=True, exist_ok=True) # malicious
        pathlib.Path(f'./cmp/httppacket/{kind}/0').mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(f'./cmp/httppacket/{kind}/1').mkdir(parents=True, exist_ok=True) # malicious
        pathlib.Path(f'./cmp/httpv1body/{kind}/0').mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(f'./cmp/httpv1body/{kind}/1').mkdir(parents=True, exist_ok=True) # malicious
        pathlib.Path(f'./cmp/httpheader/{kind}/0').mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(f'./cmp/httpheader/{kind}/1').mkdir(parents=True, exist_ok=True) # malicious

        for files in group.values():
            for file in files:
                # pprint.pprint(file)
                # label = int(file['malicious'] >= 1 or file['suspicious'] >= 1)
                label = 1
                dataset = file.replace('.cap', '.dat')
                loads(f'./newDataSet/{file}', f'{kind}/{label}/{dataset}')


def loads(fin, fout):
    fout1 = f'./cmp/tcppayload/{fout}'
    fout2 = f'./cmp/reassembly/{fout}'
    fout3 = f'./cmp/httppacket/{fout}'
    fout4 = f'./cmp/httpv1body/{fout}'
    fout5 = f'./cmp/httpheader/{fout}'
    print(f'\nExtracting file {fin} & dumping to ./cmp/*/{fout}')
    extractor = jspcap.Extractor(fin=fin, store=False, tcp=True, verbose=True, nofile=True, strict=True, extension=False, auto=False)
    for packet in extractor:
        if jspcap.TCP in packet:
            tcp = packet[jspcap.TCP]
            dumps(fout1, tcp.packet.payload or b'')
    # for packet in extractor.reassembly.tcp:
    #     payload = packet['payload']
    #     report = jspcap.analyse(io.BytesIO(payload), len(payload))
    #     if report.protochain and jspcap.HTTP in report.protochain:
    #         dumps(fout2, report.info.raw.packet or b'')
    #         dumps(fout3, report.info.raw.body or b'')
    for reassembly in extractor.reassembly.tcp:
        for packet in reassembly.packets:
            if packet.protochain and jspcap.HTTP in packet.protochain:
                dumps(fout2, packet.info.raw.packet or b'')
                dumps(fout3, packet.info.raw.packet or b'')
                dumps(fout4, packet.info.raw.body or b'')
                dumps(fout5, packet.info.raw.header or b'')
            else:
                dumps(fout2, packet.info or b'')


def dumps(name, byte):
    # print(f'Writing to file {name}')
    with open(name, 'ab') as file:
        file.write(byte)


def main():
    # name = os.path.splitext(sys.argv[1])[0]
    # name = input('File name: ')
    # name = os.path.splitext(name)[0]
    # print(name)
    # stream = make_steam(name)
    make_dataset()


main()
# if __name__ == '__mian__':
#     main()
