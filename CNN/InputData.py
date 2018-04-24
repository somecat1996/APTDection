import csv
import numpy as np


def ReadData(path, trainrate=0.8):
    csv_reader = csv.reader(open(path, 'r'))
    packets = []
    labels = []
    for row in csv_reader:
        packets.append(row[0])
        labels.append(row[1])
    packets = np.asarray(packets)
    labels = np.asarray(labels)
    shuffle = np.arange(len(packets))
    np.random.shuffle(shuffle)
    packets = packets[shuffle]
    labels = labels[shuffle]

    s = np.int(len(packets) * trainrate)
    packets_train = packets[:s]
    labels_train = labels[:s]
    packets_eval = packets[s:]
    labels_eval = labels[s:]
    return packets_train, labels_train, packets_eval, labels_eval
