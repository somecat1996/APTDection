import os
import json
import datetime as dt


def readReportList(path):
    with open(os.path.join(path, "index.json"), 'r') as f:
        index = json.load(f)
    return index

def writeUA(index):
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
            flag = True
            for j in UA:
                if name == j['name'] and type == j['type']:
                    flag = False
                    if time < j['stime']:
                        j['stime'] = time
                    elif time > j['etime']:
                        j['etime'] = time
                    j['src'].append(src)
                    j['dst'].append(dst)
                    break
            if flag:
                UA.append({
                    "name": name,
                    "type": type,
                    "stime": time,
                    "etime": time,
                    "info": info,
                    "src": [src],
                    "dst": [dst]
                })
    with open("UA.json", 'w') as f:
        json.dump(f, UA)

def writeInnerIP(index):
    innerIP = list()
    if os.path.isfile("innerIP.json"):
        with open("innerIP.json", 'r') as f:
            innerIP.extend(json.load(f))
    for file in index:
        tmp_data = json.load(open(file, 'r'))
        for i in tmp_data:
            name = i['UA']
            type = i['is_malicious']
            time = dt.datetime.fromisoformat(i['time'])
            info = i['info']
            src = i['srcIP']
            dst = i['dstIP']
            flag = True
            for j in UA:
                if name == j['name'] and type == j['type']:
                    flag = False
                    if time < j['stime']:
                        j['stime'] = time
                    elif time > j['etime']:
                        j['etime'] = time
                    j['src'].append(src)
                    j['dst'].append(dst)
                    break
            if flag:
                UA.append({
                    "name": name,
                    "type": type,
                    "stime": time,
                    "etime": time,
                    "info": info,
                    "src": [src],
                    "dst": [dst]
                })
    with open("innerIP.json", 'w') as f:
        json.dump(f, innerIP)

if __name__ == "__main__":
    index = readReportList("./report")
    writeInnerIP(index)
    writeUA(index)

