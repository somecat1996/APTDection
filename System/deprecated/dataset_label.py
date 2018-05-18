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


def make_steam(name, count):
    print(f'Labeling for {name}.pcap{count}')
    pathlib.Path(f'./stream/{name}_{count}/tmp').mkdir(parents=True, exist_ok=True)
    shutil.copy(f'../httpdump/{name}.pcap{count}', f'./stream/{name}_{count}/{name}_{count}.pcap')

    builder = webgraphic()
    builder.read_in(f'./stream/{name}_{count}/{name}_{count}.pcap')
    IPS = builder.GetIPS()
    print('\n', IPS, '\n')

    stream = StreamManager(f'{name}_{count}.pcap')
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


def main(index):
    count = str(index).rjust(3, '0')
    name = 'wanyong80'
    # name = input('File name: ')
    # name = os.path.splitext(name)[0]
    # print(name)
    stream = make_steam(name, count)

    count = ext[-3:]
    name = f'wanyong80_{count}'
    make_record(name, stream)

for i in range(4, 21):
    main(i)
for i in range(31, 40):
    main(i)
# if __name__ == '__mian__':
#     main()
