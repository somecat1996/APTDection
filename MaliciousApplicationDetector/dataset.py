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

# import jspcap

from fingerprints.fingerprintsManager import *
from StreamManager.StreamManager4 import *
from webgraphic.webgraphic import *


__all__ = ['dataset']


ROOT = os.path.dirname(os.path.abspath(__file__))


FLOW_DICT = {
#    'Browser_PC' : lambda stream: stream.GetBrowserGroup_PC(),
    'Background_PC' : lambda stream: stream.GetBackgroudGroup_PC(),
#    'Browser_Phone' : lambda stream: stream.GetBrowserGroup_Phone(),
    'Background_Phone' : lambda stream: stream.GetBackgroudGroup_Phone(),
    'Suspicious' : lambda stream: stream.GetSuspicious(),
}


_worker_chklist = list()
_worker_labeled = False
_worker_alive = list()
_worker_count = 0
_worker_pool = tuple()
_worker_mode = 0
_worker_max = mp.cpu_count()
_worker_num = mp.Value('I', 0)



class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return {'val': obj.hex(), '_spec_type': 'bytes'}
        else:
            return super().default(obj)


def object_hook(obj):
    _spec_type = obj.get('_spec_type')
    if _spec_type:
        if _spec_type == 'bytes':
            return bytes.fromhex(obj['val'])
        raise ParseError(f'unknown {_spec_type}')
    return obj


def dataset(*args, mode, labeled=False):
    """Cook dataset for CNN.

    Positional arguments:
        * path -- str, absolute source path

    Keyword arguments:
        * mode -- int, preparation mode
            |--> 0 -- stage 0, do labeling & no fingerprints
            |--> 1 -- stage 1, do labeling & do fingerprints
            |--> 2 -- stage 2, no labeling & do fingerprints
        * labeled -- bool, if source already labeled

    Returns:
        * dict -- dataset index

    """
    global _worker_chklist, _worker_labeled, _worker_alive, _worker_pool, _worker_mode

    # set signal handler
    signal.signal(signal.SIGUSR1, make_worker)

    # initialise macros
    _worker_labeled = bool(labeled)
    _worker_alive = mp.Array('I', [ True for _ in args ])
    _worker_pool = tuple(args)
    _worker_mode = int(mode)
    print(args)
    # start process
    make_worker()

    # check status
    while any(_worker_alive):
        time.sleep(random.randint(0, dt.datetime.now().second))
    chklist = [ proc.join() for proc in _worker_chklist ]
    if len(chklist) != len(args):
        raise RuntimeWarning(f'expected {len(agrs)} workers, but {len(chklist)} found')
    print(f'Dataset ready @ {make_path(f"dataset")}')

    # dump index.json
    return make_index(retrieve=True)


def worker(path, *, mode, _count=0):
    """Prepare dataset for CNN."""
    global _worker_labeled, _worker_alive, _worker_num
    print(f'Worker No.{_count+1} @mode_{mode} on {path}')

    # print(f'[{time.time()}] Worker A_{_count} @ {path} start')
    # time.sleep(random.randint(0, dt.datetime.now().second))
    # print(f'[{time.time()}] Worker A_{_count} @ {path} done')

    _signal_sent = False
    try:
        # extract name
        root, file = os.path.split(path)
        name, ext = os.path.splitext(file)

        # duplicate PCAP file
        while pathlib.Path(make_path(f'stream/{name}')).exists():
            name = f'{name}_{int(time.time())}'
        pathlib.Path(make_path(f'stream/{name}/tmp')).mkdir(parents=True, exist_ok=True)
        shutil.copy(path, make_path(f'stream/{name}/{name}.pcap'))

        # make files
        sdict = make_steam(name, mode=mode,             # make stream
                            _labeled=_worker_labeled)
        print('Stream!', sdict)
        os.kill(os.getppid(), signal.SIGUSR1)           # send signal
        _signal_sent = True                             # sent signal
        index = make_dataset(name, sdict, mode=mode,    # make dataset
                                fingerprint=_worker_labeled)
        print('Dataset!', index)
        # aftermath
        if path != make_path(f'stream/{name}/{name}.pcap'):
            os.remove(make_path(f'stream/{name}/{name}.pcap'))
    except BaseException as error:
        print(str(error))
        if not _signal_sent:
            os.kill(os.getppid(), signal.SIGUSR1)       # send signal
        raise error

    # print(f'[{time.time()}] Worker B_{_count} @ {path} start')
    # time.sleep(random.randint(0, dt.datetime.now().second))
    # print(f'[{time.time()}] Worker B_{_count} @ {path} done')

    # update status
    if _worker_labeled or mode == 2:
        _worker_num.value -= 1
    _worker_alive[_count] = False


def make_path(path):
    """Make path."""
    return os.path.join(ROOT, path)


def make_worker(signum=None, stack=None):
    """Create process."""
    global _worker_chklist, _worker_labeled, _worker_count, _worker_alive, _worker_num

    # check boundary
    if _worker_count >= len(_worker_pool):
        return

    # wait process
    while _worker_num.value >= _worker_max:
        time.sleep(random.randint(0, dt.datetime.now().second))

    # create process
    proc = mp.Process(target=worker, args=(_worker_pool[_worker_count],),
                        kwargs={'mode': _worker_mode, '_count': _worker_count})
    proc.start()
    _worker_chklist.append(proc)

    # ascend count
    _worker_count += 1
    if _worker_labeled or _worker_mode == 2:
        _worker_num.value += 1


def make_steam(name, *, mode, _labeled):
    """Extract TCP streams.

    Positional arguments:
        * name -- str, dataset source name

    Keyword arguments:
        * mode -- int, preparation mode
            |--> 0 -- stage 0, do labeling & no fingerprints
            |--> 1 -- stage 1, do labeling & do fingerprints
            |--> 2 -- stage 2, no labeling & do fingerprints
        * _labeled -- bool, if source already labeled

    Returns:
        * dict -- dataset labels

    """
    print(f'Start labeling for {name}...')

    # already labeled
    if _labeled:
        print(f'Finished labeling for {name}...')
        return

    # Web Graphic
    builder = webgraphic()
    builder.read_in(make_path(f'stream/{name}/{name}.pcap'))
    IPS = builder.GetIPS()

    # Stream Manager
    stream = StreamManager(make_path(f'stream/{name}/{name}.pcap'))
    stream.generate()
    stream.classify(IPS)
    stream.Group()
    if mode != 2:
        stream.labelGroups()
    print(f'Finished labeling for {name}...')

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
    with open(make_path(f'stream/{name}/stream.json'), 'w') as json_file:
        json.dump(record, json_file, cls=JSONEncoder)
    return record


def make_fingerprint(name, label, *, mode):
    """Make fingerprint."""
    if mode == 1:
        fp = fingerprintManager()
        fp.GenerateAndUpdate(make_path(f'stream/{name}/tmp'), label)


def make_dataset(name, labels=None, *, mode, overwrite=True, fingerprint=False):
    """Make dataset.

    Positional arguments:
        * name -- str, dataset source name
        * labels -- dict, dataset labels

    Keyword arguments:
        * mode -- int, preparation mode
            |--> 0 -- stage 0, do labeling & no fingerprints
            |--> 1 -- stage 1, do labeling & do fingerprints
            |--> 2 -- stage 2, no labeling & do fingerprints
        * overwrite -- bool, if overwrite existing files
        * fingerprint -- bool, if generate and/or update fingerprints

    Returns:
        * dict -- dataset index

    """
    print(f'Start making dataset for {name}...')

    # load JSON file
    if labels is None:
        with open(make_path(f'stream/{name}/stream.json'), 'r') as file:
            labels = json.load(file, object_hook=object_hook)

    fplist = list()
    for kind, group in labels.items():
        # only make dataset for type Background PC
        if kind != 'Background_PC':     continue

        # make directory
        pathlib.Path(make_path(f'dataset/{name}/{kind}/0')).mkdir(parents=True, exist_ok=True) # safe
        pathlib.Path(make_path(f'dataset/{name}/{kind}/0')).mkdir(parents=True, exist_ok=True) # malicious

        # make fingerprints
        if fingerprint:
            make_fingerprint(name, group, mode=mode)

        # identify figerprints
        group_keys = group.keys()
        if mode == 2:
            fp = fingerprintManager()
            fpreport = fp.Identify(make_path(f'stream/{name}/tmp'), group)
            for ipua in fpreport['is_malicious']:
                fplist += group[ipua]
            group_keys = fpreport['new_app']

            with open(make_path(f'stream/{name}/fingerprint.json'), 'w') as jsonfile:
                json.dump(fpreport, jsonfile, cls=JSONEncoder)
            print(fpreport)

        # enumerate files
        for ipua in group_keys:
            for file in group[ipua]:
                label = int(file['is_malicious'])
                srcfile = file['filename']
                dataset = file['filename'].replace('.pcap', '.dat')
                loads(file['http'],#make_path(f'stream/{name}/tmp/{srcfile}'),
                        make_path(f"dataset/{name}/{kind}/{label}/{dataset}"), remove=overwrite)
    print(f'Finished making dataset for {name}...')

    # dump index.json
    return make_index(fp=fplist)


def loads(fin, fout, *, remove):
    """Extract PCAP file."""
    # check if file exists
    if pathlib.Path(fout).exists():
        if remove:  os.remove(fout)
        else:       return

    # extraction procedure
    # print(f'Start extracting {fin}...')
    # extractor = jspcap.extract(fin=fin, store=False, nofile=True, verbose=True,
    #                             tcp=True, strict=True, extension=False)
    # print(f'Finished extracting {fin}...')

    # fetch reassembly
    print(f'Start dumping to {fout}...')
    # for reassembly in extractor.reassembly.tcp:
    #     for packet in reassembly.packets:
    #         if jspcap.HTTP in packet.protochain:
    #             dumps(fout, packet.info.raw.header or b'')
    for http in fin:
        dumps(fout, http.split(b'\r\n\r\n')[0])
    print(f'Finished dumping to {fout}...')


def dumps(name, byte):
    """Dump dataset."""
    with open(name, 'ab') as file:
        file.write(byte)


def make_index(*, fp=None, retrieve=False):
    """Dump index.json."""
    # initialise index
    index = {
        'Browser_PC' : {'0': list(), '1': list()},
        'Background_PC' : {'0': list(), '1': list()},
        'Browser_Phone' : {'0': list(), '1': list()},
        'Background_Phone' : {'0': list(), '1': list()},
        'Suspicious' : {'0': list(), '1': list()},
    }

    # walk dataset
    for path in os.listdir(make_path('dataset')):
        for kind in index:
            for root, _, files in os.walk(make_path(f'dataset/{path}/{kind}/1')):
                for file in files:
                    if os.path.getsize(f'{root}/{file}'):
                        index[kind]['1'].append(f'{root}/{file}')
            for root, _, files in os.walk(make_path(f'dataset/{path}/{kind}/0')):
                for file in files:
                    if os.path.getsize(f'{root}/{file}'):
                        index[kind]['0'].append(f'{root}/{file}')

    # fingerprint report
    if fp is not None:
        with open(make_path(f'dataset/{time.time()}_'
                            f'{random.randint(0, dt.datetime.now().second)}.fp'), 'w') as file:
            json.dump({'is_malicious': fp}, file, cls=JSONEncoder)

    # retrieve report
    if retrieve:
        fp = list()
        for item in os.listdir(make_path(f'dataset')):
            if os.path.splitext(item)[1] == '.fp':
                with open(make_path(f'dataset/{item}'), 'r') as file:
                    fp += json.load(file, object_hook=object_hook)['is_malicious']
                os.remove(make_path(f'dataset/{item}'))
        index['is_malicious'] = fp

    # dump index.json
    with open(make_path('dataset/index.json'), 'w') as index_file:
        json.dump(index, index_file, cls=JSONEncoder)
    return index


if __name__ == '__main__':
    tflag = int(sys.argv[1])
    modec = int(sys.argv[2])
    paths = sys.argv[3:]
    if tflag:
        sys.exit(dataset(*paths, mode=modec))
    for path in paths:
        root, file = os.path.split(path)
        name, ext = os.path.splitext(file)
        index = make_dataset(name, mode=modec)
    sys.exit(make_index(retrieve=True))
