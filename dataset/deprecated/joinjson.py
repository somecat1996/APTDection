# -*- coding: utf-8 -*-


import json
import os
import sys


KIND = (
    'Browser_PC',
    'Backgroud_PC',
    'Browser_Phone',
    'Backgroud_Phone',
    'Suspicious',
)

JSON = dict()


name = os.path.splitext(sys.argv[1])[0]
for kind in KIND:
    with open(f'./dataset/{name}/{kind}/stream.json', 'r') as file:
        JSON[kind] = json.load(file)
    os.remove(f'./dataset/{name}/{kind}/stream.json')
with open(f'./dataset/{name}/stream.json', 'w') as json_file:
    json.dump(JSON, json_file)
