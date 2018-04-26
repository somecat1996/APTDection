import os
import numpy as np


def ReadData(path, trainrate=0.8):
    files = [x for x in os.listdir(path)]
    packets = []
    labels = []
    for file in files:
        packet = []
        payload = open(path+file, 'rb').read()
        if len(payload) < 784:
            payload += (784 - len(payload)) * b'\x00'
        for i in payload:
            packet.append(i)
        packets.append(packet)
        labels.append(int(file[-1]))
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

if __name__ == "__main__":
    packets_train, labels_train, packets_eval, labels_eval = ReadData("../DataPath/")
    for i in range(len(packets_train)):
        print(packets_train[i])
        print(len(packets_train[i]))
        print(labels_train[i])
    for i in range(len(packets_eval)):
        print(packets_eval[i])
        print(len(packets_eval[i]))
        print(labels_eval[i])