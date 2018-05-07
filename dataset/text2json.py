# -*- coding: utf-8 -*-


import ast
import json
import os
# import re
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
with open(f'./stream/{name}/{name}.txt', 'r') as file:
    for index, line in enumerate(file):
        JSON[KIND[index]] = ast.literal_eval(line)
        with open(f'./dataset/{name}/stream.json', 'w') as json_file:
            # json_file.write(re.sub('\'', '"', line))
            json.dump(JSON, json_file)
