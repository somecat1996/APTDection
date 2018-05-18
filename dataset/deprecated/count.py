# -*- coding: utf-8 -*-


import json


KIND = ('tcppayload', 'reassembly', 'httppacket', 'httpheader', 'httpv1body')

for kind in KIND:
    with open(f'./cmp/{kind}/index.json') as file:
        JSON = json.load(file)
        print(kind, len(JSON['Backgroud_PC']['0']), len(JSON['Backgroud_PC']['1']))
