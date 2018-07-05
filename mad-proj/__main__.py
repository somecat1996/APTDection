# -*- coding: utf-8 -*-


import multiprocessing
import signal

import pcapkit
import scapy.all as scapy


IFACE = 'eth0'
TIMEOUT = 1000


def main(*, iface=None):
    """Main interface for MAD."""
    signal.signal(signal.SIGUSR1, make_worker)

    if iface is not None:
        global IFACE
        IFACE = iface

    make_worker()


def make_worker():
    """Create child process."""
    proc = multiprocessing.Process(target=start_worker)
    proc.start()


def start_worker():
    """Start child process."""
    # first, we sniff packets using Scapy
    # set time limit and interface
    scapy.sniff(timeout=TIMEOUT, iface=IFACE)

    # then, we trace and make index for TCP flow of packets sniffed
    # using PyPCAPKit, whose interface is to be done by tmrw
    index = pcapkit.trace(...)

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
