# -*- coding: utf-8 -*-


# NB: fingerprint algorithms are not inclued yet


import datetime
import json
import multiprocessing as mp
import os
import pathlib
import time
import shutil
import signal
import sys

import jspcap

from MaliciousApplicationDetector.StreamManager.StreamManager4 import *
from MaliciousApplicationDetector.webgraphic.webgraphic import *


__all__ = ['dataset']


FLOW_DICT = {
    'Browser_PC' : lambda stream: stream.GetBrowserGroup_PC(),
    'Background_PC' : lambda stream: stream.GetBackgroudGroup_PC(),
    'Browser_Phone' : lambda stream: stream.GetBrowserGroup_Phone(),
    'Background_Phone' : lambda stream: stream.GetBackgroudGroup_Phone(),
    'Suspicious' : lambda stream: stream.GetSuspicious(),
}


_worker_alive = True
_worker_count = 0
_worker_mode = 0
_worker_pool = list()


def dataset(*args, mode):
    """Cook dataset for CNN.

    Positional arguments:
        * path -- str, absolute source path

    Keyword arguments:
        * mode -- int, preparation mode
            |--> 0 -- stage 0, do labeling & no fingerprints
            |--> 1 -- stage 1, do labeling & do fingerprints
            |--> 2 -- stage 2, no labeling & do fingerprints

    Returns:
        * dict -- dataset index

    """
    signal.signal(signal.SIGUSR1, make_worker)
    global _worker_pool, _worker_mode
    _worker_pool = list(args)
    _worker_mode = int(mode)
    make_worker()

    while _worker_alive:
        time.sleep(datetime.datetime.now().second)
    return make_index()


def prepare(path, *, mode):
    """Prepare dataset for CNN.

    Positional arguments:
        * path -- str, absolute source path

    Keyword arguments:
        * mode -- int, preparation mode
            |--> 0 -- stage 0, do labeling & no fingerprints
            |--> 1 -- stage 1, do labeling & do fingerprints
            |--> 2 -- stage 2, no labeling & do fingerprints

    Returns:
        * dict -- dataset index

    """
    # extract name
    root, file = os.path.split(path)
    name, ext = os.path.splitext(file)

    # duplicate PCAP file
    if pathlib.Path(f'./stream/{name}').exists():
        name = f'{name}_{int(time.time())}'
    pathlib.Path(f'./stream/{name}').mkdir(parents=True, exist_ok=True)
    shutil.copy(path, f'./stream/{name}/{name}.pcap')

    # make files
    sdict = make_steam(name, mode=mode)         # make stream
    os.kill(os.getppid(), signal.SIGUSR1)       # send signal
    index = make_dataset(name, labels=sdict)    # make dataset

    # aftermath
    if path != f'./stream/{name}/{name}.pcap':
        os.remove(f'./stream/{name}/{name}.pcap')
    return index


def make_worker(signum=None, stack=None):
    global _worker_count, _worker_alive
    if _worker_count >= len(_worker_pool):
        return

    proc = mp.Process(target=prepare, args=(_worker_pool[_worker_count],),
                kwargs={'mode': _worker_mode})
    proc.start()

    _worker_count += 1
    if _worker_count >= len(_worker_pool):
        proc.join()
        _worker_alive = False


def make_steam(name, *, mode):
    """Extract TCP streams.

    Positional arguments:
        * name -- str, dataset source name

    Keyword arguments:
        * mode -- int, preparation mode
            |--> 0 -- stage 0, do labeling & no fingerprints
            |--> 1 -- stage 1, do labeling & do fingerprints
            |--> 2 -- stage 2, no labeling & do fingerprints

    Returns:
        * dict -- dataset labels

    """
    # Web Graphic
    builder = webgraphic()
    builder.read_in(f'./stream/{name}/{name}.pcap')
    IPS = builder.GetIPS()

    # Stream Manager
    stream = StreamManager(f'{name}.pcap')
    stream.generate()
    stream.classify(IPS)
    if mode == 2:   # do lebeling
        stream.Group()
    else:           # no labeling
        stream.labelGroups()

    # dump stream.json
    return make_record(name, stream)


def make_record(name, stream):
    """Dump steam.json."""
    record = dict()
    for kind, group in FLOW_DICT.items():
        record[kind] = group(stream)

    with open(f'./stream/{name}/stream.json', 'w') as json_file:
        json.dump(record, json_file)
    return record


def make_dataset(name, *, labels=None):
    """Make dataset.

    Positional arguments:
        * name -- str, dataset source name

    Keyword arguments:
        * labels -- dict, dataset labels

    Returns:
        * dict -- dataset index

    """
    # load JSON file
    if labels is None:
        with open(f'./stream/{name}/strea.json', 'r') as file:
            labels = json.load(file)
    
    for kind, group in labels.items():
        # only make dataset for type Background PC
        if kind != 'Background_PC':     continue

        # make directory
        pathlib.Path(f'./dataset/{name}/{kind}/0').mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(f'./dataset/{name}/{kind}/1').mkdir(parents=True, exist_ok=True) # malicious
        
        # enumerate files
        for files in group.values():
            for file in files:
                label = int(file['ismalicious'])
                srcfile = file["filename"]
                dataset = file['filename'].replace('.pcap', '.dat')
                loads(f'./stream{name}/tmp/{srcfile}', f"./dataset/{name}/{kind}/{label}/{dataset}")

    # dump index.json
    return make_index()


def loads(fin, fout):
    """Extract PCAP file."""
    # empty existing file
    os.system(f'> {fout}')

    # extraction procedure
    extractor = jspcap.extract(fin=fin, store=False, nofile=True, 
                                tcp=True, strict=True, extension=False)

    # fetch reassembly
    for reassembly in extractor.reassembly.tcp:
        for packet in reassembly.packets:
            if jspcap.HTTP in packet.protochain:
                dumps(fout, packet.info.raw.header or b'')


def dumps(name, byte):
    """Dump dataset."""
    with open(name, 'ab') as file:
        file.write(byte)


def make_index():
    """Dump index.json."""
    index = {
        'Browser_PC' : {0: list(), 1: list()},
        'Background_PC' : {0: list(), 1: list()},
        'Browser_Phone' : {0: list(), 1: list()},
        'Background_Phone' : {0: list(), 1: list()},
        'Suspicious' : {0: list(), 1: list()},
    }

    for path in os.listdir('./dataset'):
        for kind in index:
            for root, _, files in os.walk(f'./dataset/{path}/{kind}/1'):
                for file in files:
                    if os.path.getsize(f'{root}/{file}'):
                        index[kind][1].append(f'{root}/{file}')
            for root, _, files in os.walk(f'./dataset/{path}/{kind}/0'):
                for file in files:
                    if os.path.getsize(f'{root}/{file}'):
                        index[kind][0].append(f'{root}/{file}')

    with open('./dataset/index.json', 'w') as index_file:
        json.dump(index, index_file)
    return index


if __name__ == '__main__':
    modec = int(sys.argv[1])
    paths = sys.argv[2:]
    dataset(*paths, mode=modec)
