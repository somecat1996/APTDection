# -*- coding: utf-8 -*-


import collections
import json
import os
import pathlib


def make_stream():
    file_dict = collections.defaultdict(dict)
    for path in os.listdir('/usr/local/mad/dataset'):
        if not os.path.isfile(f'/usr/local/mad/dataset/{path}/group.json'): continue
        with open(f'/usr/local/mad/dataset/{path}/group.json') as json_file:
            labels = json.load(json_file)
        path = path.split('.')[0]
        for kind, group in labels.items():
            for ipua in group:
                for file in group[ipua]:
                    file['ipua'] = ipua
                    name = pathlib.Path(file['filename']).stem
                    file_dict[path][name] = file

    stream = dict()
    for kind in {'Background_PC',}:
        stream[kind] = collections.defaultdict(list)
        dat_files = os.listdir(f'/usr/local/mad/retrain/dataset/{kind}/1')
        for file in dat_files:
            stem = pathlib.Path(file).stem
            path, name = stem.split('_', 1)
            file = file_dict[path].get(name)
            if file:
                file['is_malicious'] = 1
                stream[kind][file['ipua']].append(file)

        dat_files = os.listdir(f'/usr/local/mad/retrain/dataset/{kind}/0')
        for file in dat_files:
            stem = pathlib.Path(file).stem
            path, name = stem.split('_', 1)
            file = file_dict[path].get(name)
            if file:
                file['is_malicious'] = 1
                stream[kind][file['ipua']].append(file)

    with open('/usr/local/mad/retrain/stream.json', 'w') as file:
        json.dump(stream, file)

    return stream


if __name__ == '__main__':
#    import pprint
#    pprint.pprint(make_stream())
    make_stream()

