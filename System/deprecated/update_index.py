# -*- coding: utf-8 -*-


import json
import os
import shutil


def update(name):
    os.remove(f'../pkt2flow/dataset/{name}/stream.json')
    with open(f'../pkt2flow/stream/{name}/stream.json', 'r') as file:
        labels = json.load(file)

    for kind, group in labels.items():
        for files in group.values():
            for file in files:
                oldlabel = int(file['malicious'] >= 1 or file['suspicious'] >= 1)
                newlabel = int(file['malicious'] >= 1 or file['suspicious'] >= 2)
                if oldlabel != newlabel:
                    dataset = file['filename'].replace('pcap', 'dat')
                    shutil.move(f'../dataset/{name}/{kind}/{oldlabel}/{dataset}', f'../dataset/{name}/{kind}/{newlabel}/{dataset}')

for index in range(0, 40):
    if index == 18: continue
    update(f"wanyong80_{str(index).rjust(3, '0')}")
