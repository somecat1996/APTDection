# -*- coding: utf-8 -*-


import collections
import multiprocessing
import signal
import subprocess

import pcapkit
import pcapkit.all
import scapy.all


IFACE = 'eth0'
TIMEOUT = 1000
RETRAIN = False


def main(*, iface=None):
    """Main interface for MAD."""
    signal.signal(signal.SIGUSR1, make_worker)
    signal.signal(signal.SIGUSR2, retrain_cnn)

    if iface is not None:
        global IFACE
        IFACE = iface

    make_worker()


def retrain_cnn():
    """Run retrain process."""
    # if already under retrain do nothing
    if RETRAIN:     return

    # update retrain flag
    global RETRAIN
    RETRAIN = True

    # start retrain
    run_retrain(...)


def make_worker():
    """Create child process."""
    proc = multiprocessing.Process(target=start_worker)
    proc.start()


def start_worker():
    """Start child process."""
    # first, we sniff packets using Scapy
    # set time limit and interface
    sniffed = scapy.all.sniff(timeout=TIMEOUT, iface=IFACE)

    # now, we send a signal to the parent process
    # to create a new process and continue
    os.kill(os.getppid(), signal.SIGUSR1)

    # then, we trace and make index for TCP flow of packets sniffed
    # using PyPCAPKit, whose interface is to be done by tmrw
    traceflow = pcapkit.trace()
    for count, packet in enumerate(sniffed):
        flag, data = pcapkit.scapy_tcp_traceflow(packet, count=count)
        if flag:    traceflow(data)
    traceindex = traceflow.index

    index = list()
    for flow in traceindex:
        templist = list()
        for number in flow.index:
            analysis = pcapkit.analyse(file=bytes(sniffed[number]['TCP'].payload))
            if pcapkit.protocols.application.httpv1.HTTPv1 in analysis.protochain:
                templist.append(analysis.info.get('header', dict()).get('User-Agent', 'UnknownUA'))
        index.append(pcapkit.all.Info(flow, ua=collections.Counter(templist).most_common(1)[0][0]))

    # afterwards, we will work on each flow
    for flow in index:
        # generate WebGraphic & fingerprints for each flow
        # through reconstructed functions and methods
        group = make_group(...)

        # and make dataset for each flow in accordance with the group
        # using PyPCAPKit with its reassembly interface
        for ipua in group:
            for file in group[ipua]:
                make_dataset(...)

    # and now, time for the neural network
    # reports should be placed in a certain directory
    run_cnn(...)


if __name__ == '__main__':
    import sys
    sys.exit(main())
