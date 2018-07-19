import os
import json
import datetime as dt


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
        for i in tmp_data:
            name = i['UA']
            type = i['is_malicious']
            time = dt.datetime.fromisoformat(i['time'])
            info = i['info']
            src = i['srcIP']
            dst = i['dstIP']

if __name__ == "__main__":
    pass