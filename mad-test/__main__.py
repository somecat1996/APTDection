# -*- coding: utf-8 -*-
"""MAD -- Malicious Application Detector

/usr/local/mad/
    |-- mad.log                                 # log file for RPC (0-start; 1-stop; 2-retrain; 3-ready)
    |-- fingerprint.pickle                      # pickled fingerprint database
    |-- dataset/                                # where all dataset go
    |   |-- YYYY-MM-DDTHH:MM:SS.US/             # dataset named after ISO timestamp
    |   |   |-- flow.json                       # TCP flow index record
    |   |   |-- group.json                      # WebGraphic group record
    |   |   |-- filter.json                     # fingerprint filter report
    |   |   |-- stream/                         # where stream files go
    |   |   |   |-- IP_PORT-IP_PORT-TS.pcap     # temporary stream PCAP files
    |   |   |   |-- ...
    |   |   |-- Background_PC/                  # where Background_PC dataset files go
    |   |       |-- 0/                          # clean ones
    |   |       |   |-- IP_PORT-IP_PORT-TS.dat  # dataset file
    |   |       |   |-- ...
    |   |       |-- 1/                          # malicious ones
    |   |           |-- IP_PORT-IP_PORT-TS.dat  # dataset file
    |   |           |-- ...
    |   |-- ...
    |-- report/                                 # where CNN prediction report go\
    |   |-- Background_PC/                      # Background_PC reports
    |   |   |-- index.json                      # report index file
    |   |   |-- YYYY-MM-DDTHH:MM:SS.US.json     # report named after dataset
    |   |-- ...
    |-- model/                                  # where CNN model go
    |   |-- Background_PC/                      # Background_PC models
    |   |   |-- ...
    |   |-- ...
    |-- retrain/                                # where CNN retrain data go
        |-- dateset/                            # dataset for retrain procedure
        |   |-- Background_PC/                  # Background_PC retrain dataset
        |       |-- 0/                          # clean ones
        |       |   |-- YYYY-MM-DDTHH:MM:SS.US-IP_PORT-IP_PORT-TS.dat
        |       |   |-- ...
        |       |-- 1/                          # malicious ones
        |           |-- YYYY-MM-DDTHH:MM:SS.US-IP_PORT-IP_PORT-TS.dat
        |           |-- ...
        |-- stream/                             # stream PCAP for retrain procedure
            |-- stream.json                     # stream index for retrain
            |-- Background_PC/                  # Background_PC retrain stream file
                |-- 0/                          # clean ones
                |   |-- YYYY-MM-DDTHH:MM:SS.US-IP_PORT-IP_PORT-TS.pcap
                |   |-- ...
                |-- 1/                          # malicious ones
                    |-- YYYY-MM-DDTHH:MM:SS.US-IP_PORT-IP_PORT-TS.pcap
                    |-- ...

"""
import collections
import datetime as dt
import json
import multiprocessing
import os
import pathlib
import shlex
import shutil
import signal
import subprocess
import sys
import time

# import chardet
# import pcapkit.all
import scapy.all

from fingerprints.fingerprintsManager import *
from StreamManager.StreamManager4 import *
from webgraphic.webgraphic import *


# testing macros
FILE = NotImplemented
COUNT = -1


ROOT = os.path.dirname(os.path.abspath(__file__))
                    # file root path
MODE = 3            # 1-initialisation; 2-migeration; 3-prediction; 4-adaptation
PATH = '/'          # path of original data
IFACE = 'eth0'      # sniff interface
TIMEOUT = 1000      # sniff timeout
RETRAIN = multiprocessing.Value('B', False)
                    # retrain flag


FLOW_DICT = {
    # 'Browser_PC' : lambda stream: stream.GetBrowserGroup_PC(),
    'Background_PC' : lambda stream: stream.GetBackgroudGroup_PC(),
    # 'Browser_Phone' : lambda stream: stream.GetBrowserGroup_Phone(),
    'Background_Phone' : lambda stream: stream.GetBackgroudGroup_Phone(),
    'Suspicious' : lambda stream: stream.GetSuspicious(),
}


MODE_DICT = {
    1 : 'train',    # initialisation
    2 : 'retrain',  # migeration
    3 : 'predict',  # prediction
    4 : 'retrain',  # apdatation
}


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


def main(*, iface=None, mode=None, path=None, _file=None):
    """Main interface for MAD."""
    # bind signals
    signal.signal(signal.SIGUSR1, make_worker)
    signal.signal(signal.SIGUSR2, retrain_cnn)

    # make paths
    for name in {'dataset', 'report', 'model', 'pcap', 'retrain/dataset', 'retrain/stream'}:
        pathlib.Path(f'/usr/local/mad/{name}').mkdir(parents=True, exist_ok=True)

    if iface is not None:
        global IFACE
        IFACE = iface

    if mode is not None:
        global MODE
        MODE = mode

    if path is not None:
        global PATH
        PATH = path

    if _file is not None:
        global FILE
        with open(_file, 'r') as file:
            FILE = json.load(file, object_hook=object_hook)

    # start procedure
    make_worker()


def retrain_cnn(*args):
    """Retrain the CNN model."""
    # if already under retrain do nothing
    if RETRAIN.value:   return
    return

    # update retrain flag
    RETRAIN.value = True

    # start retrain
    multiprocessing.Process(
        target=run_cnn,
        kwargs={'path': '/usr/local/mad/retrain/dataset',
                'ppid': os.getpid(), 'retrain': True},
    ).start()


def make_worker(*args):
    """Create child process."""
    # start child in prediction
    global MODE, COUNT
    if MODE == 3:
        if COUNT is not NotImplemented: COUNT += 1
        return multiprocessing.Process(target=start_worker).start()

    # do initialisation or migration first
    # then, keep on with prediction (if need)
    start_worker()
    if MODE == 2:
        MODE = 3
        return make_worker()


def start_worker():
    """Start child process."""
    # above all, create directory for new dataset
    # and initialise fingerprint manager
    path = pathlib.Path(f'/usr/local/mad/dataset/{dt.datetime.now().isoformat()}')
    path.mkdir(parents=True, exist_ok=True)
    fp = fingerprintManager()

    print(f'New process start @ {path}')

    # write a log file to inform state of running
    # the back-end of webpage shall check this file
    with open('/usr/local/mad/mad.log', 'at', 1) as file:
        file.write(f'0 {dt.datetime.now().isoformat()} {path}\n')

    milestone_0 = time.time()

    # first, we sniff packets using Scapy
    # or load data from an existing PCAP file
    name = make_sniff(path=path)

    milestone_1 = time.time()
    print(f'Sniffed for {milestone_1-milestone_0} seconds')

    # now, we send a signal to the parent process
    # to create a new process and continue
    # os.kill(os.getppid(), signal.SIGUSR1)

    # then, generate WebGraphic & fingerprints for each flow
    # through reconstructed functions and methods
    group = make_group(name, fp, path=path)

    milestone_2 = time.time()
    print(f'Grouped for {milestone_2-milestone_1} seconds')

    # and make dataset for each flow in accordance with the group
    # using PyPCAPKit with its reassembly interface
    make_dataset(group, fp, path=path)

    milestone_3 = time.time()
    print(f'Dumped for {milestone_3-milestone_2} seconds')

    # and now, time for the neural network
    # reports should be placed in a certain directory
    run_cnn(path=path, ppid=os.getppid())

    milestone_4 = time.time()
    print(f'Predicted for {milestone_4-milestone_3} seconds')

    # afterwards, write a log file to record state of accomplish
    # the back-end of webpage shall check this file periodically
    with open('/usr/local/mad/mad.log', 'at', 1) as file:
        file.write(f'1 {dt.datetime.now().isoformat()} {path}\n')

    # finally, remove used temporary dataset files
    # but record files should be reserved for further usage
    for name in {'Background_PC', 'stream'}:
        shutil.rmtree(os.path.join(path, name))


def make_sniff(*, path):
    """Load data or sniff packets."""
    # just sniff when prediction
    if MODE == 3:
        return '/home/ubuntu/httpdump/wanyong80.pcap024'
        return FILE[COUNT]
        # name = f'/usr/local/mad/pcap/{pathlib.Path(path).stem}.pcap'
        # sniffed = scapy.all.sniff(timeout=TIMEOUT, iface=IFACE)
        # scapy.all.wrpcap(name, sniffed)
        # return name


    # extract file, or ...
    # PATH = '../../PyPCAPKit/sample/http.pcap'
    if pathlib.Path(PATH).is_file():
        return PATH

    # files in a directory
    sniffed = list()
    for file in os.listdir(PATH):
        try:
            sniffed.extend(scapy.all.sniff(offline=f'{PATH}/{file}'))
        except scapy.error.Scapy_Exception as error:
            print('Error:', error)
    name = f'/usr/local/mad/pcap/{pathlib.Path(path).stem}.pcap'
    scapy.all.wrpcap(name, sniffed)
    return name


def make_group(name, fp, *, path):
    """Generate WebGraphic and fingerprints."""
    print(f'Now grouping packets @ {path}')

    # WebGraphic
    builder = webgraphic()
    builder.read_in(name)
    IPS = builder.GetIPS()

    # StreamManager
    stream = StreamManager(name, str(path))
    stream.generate()
    stream.classify(IPS)
    stream.Group()
    if MODE != 3:
        stream.labelGroups()

    # labels & fingerprints
    record = dict()
    for kind, group in FLOW_DICT.items():
        groups = group(stream)
        record[kind] = groups
        if MODE != 3:
            fp.GenerateAndUpdate(f'{path}/stream', groups)

    # dump record
    with open(f'{path}/group.json', 'w') as file:
        json.dump(record, file, cls=JSONEncoder)

    return record


def make_dataset(labels, fp, *, path):
    """Make dataset."""
    print(f'Making dataset @ {path}')

    fplist = list()
    for kind, group in labels.items():
        if kind != 'Background_PC':     continue

        # make directory
        pathlib.Path(f'{path}/{kind}/0').mkdir(parents=True, exist_ok=True)  # safe
        pathlib.Path(f'{path}/{kind}/1').mkdir(parents=True, exist_ok=True)  # malicious
        pathlib.Path(f'/usr/local/mad/report/{kind}').mkdir(parents=True, exist_ok=True)

        # identify figerprints
        group_keys = group.keys()
        if MODE == 3:
            fpreport = fp.Identify(f'{path}/stream', group)
            for ipua in fpreport['is_malicious']:
                fplist += group[ipua]
            group_keys = fpreport['new_app']

            # fingerprint report
            with open(f'{path}/filter.json', 'w') as file:
                json.dump(fpreport, file, cls=JSONEncoder)

        # enumerate files
        for ipua in group_keys:
            for file in group[ipua]:
                label = pathlib.Path(file['filename']).stem
                ftype = int(file['is_malicious'])
                fname = f'{path}/{kind}/{ftype}/{label}.dat'

                # remove existing files
                if pathlib.Path(fname).exists():
                    os.remove(fname)

                size = 0
                for payload in file['http']:
                    if size > 1024:     break
                    with open(fname, 'ab') as file:
                        byte = payload.split(b'\r\n\r\n')[0]
                        size += len(byte)
                        file.write(byte)
                        print(file.name)


def run_cnn(*, path, ppid, retrain=False):
    """Create subprocess to run CNN model."""
    print(f"CNN running @ {path}")

    # check mode for CNN
    mode = 4 if retrain else MODE

    # write log for start retrain
    if retrain:
        with open('/usr/local/mad/mad.log', 'at', 1) as file:
            file.write(f'2 {dt.datetime.now().isoformat()}\n')

    # run CNN subprocess
    for kind in {'Background_PC',}:
        cmd = [sys.executable, shlex.quote(os.path.join(ROOT, 'Training.py')),
                path, '/usr/local/mad/model', MODE_DICT.get(mode), kind, str(ppid)]
        subprocess.run(cmd)

    # things to do when retrain
    if retrain:
        # load group record
        with open(f'{path}/stream.json', 'r') as file:
            record = json.load(file, object_hook=object_hook)

        # update fingerprints
        fp = fingerprintManager()
        for kind in FLOW_DICT.keys():
            fp.GenerateAndUpdate(sniffed, record[kind], type=2)

        # write log for stop retrain
        with open('/usr/local/mad/mad.log', 'at', 1) as file:
            file.write(f'3 {dt.datetime.now().isoformat()}\n')

        # reset flag after retrain procedure
        RETRAIN.value = False


if __name__ == '__main__':
    sys.exit(main())
