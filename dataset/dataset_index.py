# -*- coding: utf-8 -*-


import json
import os
import pathlib


index = {
    'Browser_PC' : {
        0 : list(),
        1 : list(),
    },
    'Backgroud_PC' : {
        0 : list(),
        1 : list(),
    },
    'Browser_Phone' : {
        0 : list(),
        1 : list(),
    },
    'Backgroud_Phone' : {
        0 : list(),
        1 : list(),
    },
    'Suspicious' : {
        0 : list(),
        1 : list(),
    },
}

for path in os.listdir('./dataset'):
    for kind in index:
        for root, _, files in os.walk(f'./dataset/{path}/{kind}/1'):
            for file in files:
                index[kind][1].append(f'{root}/{file}')
        for root, _, files in os.walk(f'./dataset/{path}/{kind}/0'):
            for file in files:
                index[kind][0].append(f'{root}/{file}')

with open('./dataset/index.json', 'w') as index_file:
    json.dump(index, index_file)
