import os
import json


def readReportList(path):
    with open(os.path.join(path, "index.json"), 'r') as f:
        index = json.load(f)
    return index

def writeInnerIP(index):
    UA = list()
    if os.path.isfile("UA.json"):
        with open("UA.json", 'r') as f:
            UA.extend(json.load(f))
    for file in index:
        tmp_data = json.load(open(file, 'r'))



if __name__ == "__main__":

