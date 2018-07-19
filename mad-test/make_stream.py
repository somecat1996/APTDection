# -*- coding: utf-8 -*-


import collections
import json
import os
import pathlib


def dump_stream(labels, *, path):
    file_dict = dict()
    for kind, group in labels.items():
        for ipua in group:
            for file in group[ipua]:
                file['ipua'] = ipua
                name = pathlib.Path(file['filename']).stem
                file_dict[name] = file

    with open(os.path.join(path, 'record.json'), 'w') as json_file:
        json.dump(file_dict, json_file)


def load_stream(*, root):
    file_dict = collections.defaultdict(dict)
    for path in os.listdir('/usr/local/mad/dataset'):
        if os.path.isfile(f'/usr/local/mad/dataset/{path}/record.json'):
            with open(os.path.join(path, 'record.json')) as json_file:
                file_dict[path] = json.load(json_file)

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
                file['is_malicious'] = 0
                stream[kind][file['ipua']].append(file)

    with open(os.path.join(root, 'stream.json'), 'w') as file:
        json.dump(stream, file)

    return stream


if __name__ == '__main__':
    # import pprint
    # pprint.pprint(make_stream())
    load_stream()

