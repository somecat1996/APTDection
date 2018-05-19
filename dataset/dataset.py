# -*- coding: utf-8 -*-


import datetime as dt
import json
import multiprocessing as mp
import os
import pathlib
import random
import time
import shutil
import signal
import sys

import jspcap

from MaliciousApplicationDetector.fingerprints.fingerprintsManager import *
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


_worker_alive = list()
_worker_count = 0
_worker_mode = 0
_worker_pool = tuple()


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
    global _worker_alive, _worker_pool, _worker_mode

    # set signal handler
    signal.signal(signal.SIGUSR1, make_worker)

    # initialise macros
    _worker_alive = mp.Array('I', [ True for _ in args ])
    _worker_pool = tuple(args)
    _worker_mode = int(mode)

    # start process
    make_worker()

    # check status
    while any(_worker_alive):
        time.sleep(random.randint(0, dt.datetime.now().second))

    # dump index.json
    return make_index()


def worker(path, *, mode, _count=0):
    """Prepare dataset for CNN."""
    global _worker_alive

    # print(f'[{time.time()}] Worker A_{_count} @ {path} start')
    # time.sleep(random.randint(0, dt.datetime.now().second))
    # print(f'[{time.time()}] Worker A_{_count} @ {path} done')

    # extract name
    root, file = os.path.split(path)
    name, ext = os.path.splitext(file)

    # duplicate PCAP file
    while pathlib.Path(f'./stream/{name}').exists():
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

    # print(f'[{time.time()}] Worker B_{_count} @ {path} start')
    # time.sleep(random.randint(0, dt.datetime.now().second))
    # print(f'[{time.time()}] Worker B_{_count} @ {path} done')

    # update status
    _worker_alive[_count] = False


def make_worker(signum=None, stack=None):
    """Create process."""
    global _worker_count, _worker_alive

    # check boundary
    if _worker_count >= len(_worker_pool):
        return

    # create process
    mp.Process(target=worker, args=(_worker_pool[_worker_count],),
                kwargs={'mode': _worker_mode, '_count': _worker_count}).start()

    # ascend count
    _worker_count += 1


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
    return make_record(name, stream, mode=mode)


def make_record(name, stream, *, mode):
    """Dump steam.json."""
    # load labels
    record = dict()
    for kind, group in FLOW_DICT.items():
        record[kind] = group(stream)

    # make fingerprints
    for label in record.values():
        make_fingerprint(name, label, mode=mode)

    # dump stream.json
    with open(f'./stream/{name}/stream.json', 'w') as json_file:
        json.dump(record, json_file)
    return record


def make_fingerprint(name, label, *, mode):
    """Make fingerprint."""
    if mode != 0:
        fp = fingerprintManager()
        fp.GenerateAndUpdate(f'./stream/{name}/tmp', label)


def make_dataset(name, *, labels=None, overwrite=True, fingerprint=False):
    """Make dataset.

    Positional arguments:
        * name -- str, dataset source name

    Keyword arguments:
        * labels -- dict, dataset labels
        * overwrite -- bool, if overwrite existing files
        * fingerprint -- bool, if generate and/or update fingerprints

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

        # make fingerprints
        if fingerprint:
            make_fingerprint(name, group, mode=-1)

        # make directory
        pathlib.Path(f'./dataset/{name}/{kind}/0').mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(f'./dataset/{name}/{kind}/1').mkdir(parents=True, exist_ok=True) # malicious

        # enumerate files
        for files in group.values():
            for file in files:
                label = int(file['ismalicious'])
                srcfile = file["filename"]
                dataset = file['filename'].replace('.pcap', '.dat')
                loads(f'./stream{name}/tmp/{srcfile}', f"./dataset/{name}/{kind}/{label}/{dataset}", remove=overwrite)

    # dump index.json
    return make_index()


def loads(fin, fout, *, remove):
    """Extract PCAP file."""
    # check if file exists
    if pathlib.Path(fout).exists():
        if remove:  os.remove(fout)
        else:       return

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
    # initialise index
    index = {
        'Browser_PC' : {0: list(), 1: list()},
        'Background_PC' : {0: list(), 1: list()},
        'Browser_Phone' : {0: list(), 1: list()},
        'Background_Phone' : {0: list(), 1: list()},
        'Suspicious' : {0: list(), 1: list()},
    }

    # walk dataset
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

    # dump index.json
    with open('./dataset/index.json', 'w') as index_file:
        json.dump(index, index_file)
    return index


if __name__ == '__main__':
    modec = int(sys.argv[1])
    paths = sys.argv[2:]
    dataset(*paths, mode=modec)
