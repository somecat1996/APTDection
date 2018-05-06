# -*- coding: utf-8 -*-


import jspcap
import os
import pathlib
import re
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
    pathlib.Path(f'./stream/{name}').mkdir(parents=True, exists_ok=True)
    # shutil.copy(f'{name}.pcap', f'./stream/{name}/{name}.pcap')

    builder = webgraphic()
    builder.read_in(f'./stream/{name}/{name}.pcap')
    IPS = builder.GetIPS()
    # print(IPS)

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


def make_dataset(name, stream):
    for kind, group in FLOW_DICT.items():
        pathlib.Path(f'./dataset/{name}/{kind}/0').mkdir(parents=True, exists_ok=True) # safe
        pathlib.Path(f'./dataset/{name}/{kind}/1').mkdir(parents=True, exists_ok=True) # malicious
        for file in group(stream).values():
            label = int(file['malicious'] >= 1 or file['suspicious'] >= 1)
            loads(f'./stream/{name}/tmp/{file}', f'./dataset/{name}/{kind}/{label}/{re.sub('\.pcap', '.dat', file)}')


def loads(fin, fout):
    extractor = jspcap.Extractor(fin=fin, store=False, auto=False, nofile=True)
    for packet in extractor:
        if jspcap.HTTP in packet:
            http = frame[jspcap.HTTP]
            if http.body and 'text' in http.header['Content-Type']:
                dumps(fout, http.raw.body)


def dumps(name, byte):
    with open(name, 'ab') as file:
        file.write(byte)


if __name__ == '__mian__':
    name = os.path.splitext(sys.argv[1])[0]
    sys.exit(make_steam(name))
