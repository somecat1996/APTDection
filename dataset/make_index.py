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

for path in os.listdir('./cmp'):
    for kind in index.keys():
        for root, _, files in os.walk(f'./cmp/{path}/{kind}/1'):
            for file in files:
                print(f'{root}/{file}', os.path.getsize(f'{root}/{file}'))
                if os.path.getsize(f'{root}/{file}'):
                    index[kind][1].append(os.path.abspath(f'{root}/{file}'))
        for root, _, files in os.walk(f'./cmp/{path}/{kind}/0'):
            for file in files:
                print(f'{root}/{file}', os.path.getsize(f'{root}/{file}'))
                if os.path.getsize(f'{root}/{file}'):
                    index[kind][0].append(os.path.abspath(f'{root}/{file}'))

    with open(f'./cmp/{path}/index.json', 'w') as index_file:
        json.dump(index, index_file)
