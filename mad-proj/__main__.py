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

import chardet
import pcapkit.all
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


def main(*, iface=None, mode=None, path=None, _file=None):
    """Main interface for MAD."""
    # bind signals
    signal.signal(signal.SIGUSR1, make_worker)
    signal.signal(signal.SIGUSR2, retrain_cnn)

    # make paths
    for name in {'dataset', 'report', 'model', 'retrain/dataset', 'retrain/stream'}:
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
            FILE = json.load(file)

    # start procedure
    make_worker()


def retrain_cnn(*args):
    """Retrain the CNN model."""
    # if already under retrain do nothing
    if RETRAIN.value:   return

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

    start = time.time()

    # first, we sniff packets using Scapy
    # or load data from an existing PCAP file
    if MODE == 3:
        sniffed, index = make_sniff(path=path)
    else:
        sniffed = make_sniff(path=path)

    milestone_1 = time.time()
    print('Sniffed for %f seconds' % milestone_1-start)

    # now, we send a signal to the parent process
    # to create a new process and continue
    # os.kill(os.getppid(), signal.SIGUSR1)

    # then, we trace and make index for TCP flow of packets sniffed
    # using PyPCAPKit, whose interface is now done
    if MODE != 3:
        index = make_flow(sniffed, path=path)

    milestone_2 = time.time()
    print('Traced for %f seconds' % milestone_2-milestone_1)

    # generate WebGraphic & fingerprints for each flow
    # through reconstructed functions and methods
    group = make_group(sniffed, index, fp, path=path)

    milestone_3 = time.time()
    print('Grouped for %f seconds' % milestone_3-milestone_2)

    # and make dataset for each flow in accordance with the group
    # using PyPCAPKit with its reassembly interface
    make_dataset(sniffed, group, fp, path=path)

    milestone_4 = time.time()
    print('Made for %f seconds' % milestone_4-milestone_3)

    # and now, time for the neural network
    # reports should be placed in a certain directory
    run_cnn(path=path, ppid=os.getppid())

    milestone_5 = time.time()
    print('Run for %f seconds' % milestone_5-milestone_4)

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
    def decode(byte):
        """Try to decode bytes content."""
        if isinstance(byte, bytes):
            charset = chardet.detect(byte)['encoding']
            if charset:
                try:
                    return byte.decode(charset)
                except Exception:
                    pass
            return str(byte)[2:-1]
        return byte

    def get_url(analysis):
        """Make URL of HTTP request."""
        if analysis.info.receipt == 'request':
            host = decode(analysis.info.header.get('Host', str()))
            uri = decode(analysis.info.header.request.target)
            url = host + uri
            return url

    # just sniff when prediction
    if MODE == 3:
        # make stream using Pkt2Flow
        # name = FILE[COUNT]
        pathlib.Path(f'{path}/stream').mkdir(parents=True, exist_ok=True)
        name = '/home/ubuntu/httpdump/wanyong80.pcap024'
        cmd = shlex.split(f'pkt2flow -xv -o {path}/tmp {name}')
        subp = subprocess.run(cmd)
        print('执行命令')
        if subp.returncode != 0:
            raise RuntimeError('流转化失败！')
        os.system(f'mv {path}/tmp/tcp_nosyn/* {path}/stream/')
        os.system(f'mv {path}/tmp/tcp_syn/* {path}/stream/')
        shutil.rmtree(f'{path}/tmp')

        # Extraction and Analysis
        index = list()
        sniffed = list()
        total = len(os.listdir(f'{path}/stream'))
        for number, file in enumerate(os.listdir(f'{path}/stream')):
            print(f'{number}/{total} {file}')
            pcapfile = scapy.all.PcapReader(f'{path}/stream/{file}')
            flowlist = list()
            hostlist = list()
            templist = list()
            for packet in pcapfile:
                if scapy.all.Raw in packet:
                    analysis = pcapkit.analyse(file=bytes(packet[scapy.all.Raw].load))
                    if pcapkit.protocols.application.httpv1.HTTPv1 in analysis.protochain:
                        flowlist.append(len(sniffed))
                        hostlist.append(get_url(analysis))
                        templist.append(analysis.info.header.get('User-Agent'))
                        sniffed.append(packet)
            if flowlist:
                ua = (collections.Counter(filter(None, templist)).most_common(1) or [('UnknownUA', 1)])[0][0]
                url = tuple(filter(None, set(hostlist))) or ('none',)
                index.append(dict(
                    index=flowlist,
                    label=file,
                    UA=decode(ua),
                    URL=url,
                ))

        # dump index
        with open(f'{path}/flow.json', 'w') as file:
            json.dump(index, file)

        return sniffed, index
        # return scapy.all.sniff(offline=FILE[COUNT])
        # return scapy.all.sniff(offline='/home/ubuntu/httpdump/wanyong80.pcap024')
        # return scapy.all.sniff(timeout=TIMEOUT, iface=IFACE)

    # extract file, or ...
    PATH = '../../PyPCAPKit/sample/http.pcap'
    if pathlib.Path(PATH).is_file():
        return scapy.all.sniff(offline=PATH)

    # files in a directory
    sniffed = list()
    for file in os.listdir(PATH):
        try:
            sniffed.extend(scapy.all.sniff(offline=f'{PATH}/{file}'))
        except scapy.error.Scapy_Exception as error:
            print('Error:', error)
    return sniffed


def make_flow(sniffed, *, path):
    """Insert UA key to TraceFlow index."""
    print(f'Tracing TCP flow @ {path}')

    # TraceFlow
    traceflow = pcapkit.trace(fout=f'{path}/stream', format=pcapkit.PCAP)
    for count, packet in enumerate(sniffed):
        flag, data = pcapkit.scapy_tcp_traceflow(packet, count=count)
        if flag:    traceflow(data)
    traceindex = traceflow.index

    def decode(byte):
        """Try to decode bytes content."""
        if isinstance(byte, bytes):
            charset = chardet.detect(byte)['encoding']
            if charset:
                try:
                    return byte.decode(charset)
                except Exception:
                    pass
            return str(byte)[2:-1]
        return byte

    def get_url(analysis):
        """Make URL of HTTP request."""
        if analysis.info.receipt == 'request':
            host = decode(analysis.info.header.get('Host', str()))
            uri = decode(analysis.info.header.request.target)
            url = host + uri
            return url

    # Analysis
    index = list()
    for flow in traceindex:
        hostlist = list()
        templist = list()
        for number in flow.index:
            analysis = pcapkit.analyse(file=bytes(sniffed[number]['TCP'].payload))
            if pcapkit.protocols.application.httpv1.HTTPv1 in analysis.protochain:
                templist.append(analysis.info.header.get('User-Agent'))
                hostlist.append(get_url(analysis))
        ua = (collections.Counter(filter(None, templist)).most_common(1) or [('UnknownUA', 1)])[0][0]
        url = tuple(filter(None, set(hostlist))) or ('none',)
        index.append(pcapkit.all.Info(flow, UA=decode(ua), URL=url))

    # dump index
    with open(f'{path}/flow.json', 'w') as file:
        json.dump(index, file)

    return tuple(index)


def make_group(sniffed, index, fp, *, path):
    """Generate WebGraphic and fingerprints."""
    print(f'Now grouping packets @ {path}')

    # WebGraphic
    builder = webgraphic()
    builder.read_in(sniffed)
    IPS = builder.GetIPS()

    # StreamManager
    stream = StreamManager(index, sniffed)
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
            fp.GenerateAndUpdate(sniffed, groups, type=1)

    # dump record
    with open(f'{path}/group.json', 'w') as file:
        json.dump(record, file)

    return record


def make_dataset(sniffed, labels, fp, *, path):
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
            fpreport = fp.Identify(sniffed, group)
            for ipua in fpreport['is_malicious']:
                fplist += group[ipua]
            group_keys = fpreport['new_app']

            # fingerprint report
            with open(f'{path}/filter.json', 'w') as file:
                json.dump(fpreport, file)

        # enumerate files
        for ipua in group_keys:
            for file in group[ipua]:
                label = file['label']
                ftype = file['is_malicious']
                fname = f'{path}/{kind}/{ftype}/{label}.dat'

                # remove existing files
                if pathlib.Path(fname).exists():
                    os.remove(fname)

                # reassembly packets
                # reassembly = pcapkit.reassemble(protocol=pcapkit.TCP, strict=True)
                # for count, number in enumerate(file['index']):
                #     if count >= 1000:   break
                #     flag, data = pcapkit.scapy_tcp_reassembly(sniffed[number], count=number)
                #     if flag:    reassembly(data)

                # dump dataset
                # size = 0
                # for datagram in reassembly.datagram:
                #     if size > 1024:     break
                #     for packet in datagram.packets:
                #         if size > 1024: break
                #         if pcapkit.protocols.application.httpv1.HTTPv1 in packet.protochain:
                #             with open(fname, 'ab') as file:
                #                 byte = packet.info.raw.header or bytes()
                #                 size += len(byte)
                #                 file.write(byte)
                #                 print(file.name)
                size = 0
                for number in file['index']:
                    if size > 1024:     break
                    with open(fname, 'ab') as file:
                        byte = sniffed[number][scapy.all.Raw].load.split(b'\r\n\r\n')[0]
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
            record = json.load(file)

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
