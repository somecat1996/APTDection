import random
import os
import json


def readReportList(path):
    with open(os.path.join(path, "index.json"), 'r') as f:
        index = json.load(f)
    return index


def modifyReport(index):
    for file in index:
        tmp_file = "/usr/local/mad" + file
        tmp_data = json.load(open(tmp_file, 'r'))
        for i in tmp_data:
            if i['is_malicious']:
                k = random.randrange(100)
                if k != 1:
                    i['is_malicious'] = 0
        with open(file, 'w') as f:
            json.dump(tmp_data, f)

if __name__ == '__main__':
    index = readReportList("./Background_PC2")
    modifyReport(index)
