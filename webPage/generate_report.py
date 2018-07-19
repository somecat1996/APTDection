import os
import json


def readReportList(path):
    with open(os.path.join(path, "index.json"), 'r') as f:
        index = json.load(f)
    return index


def writeUA(index):
    UA = list()
    for file in index:
        tmp_data = json.load(open("/usr/local/mad" + file, 'r'))
        for i in tmp_data:
            name = i['UA']
            type = i['is_malicious']
            time = i['time']
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
                    if src not in j['srcIP']:
                        j['srcIP'].append(src)
                    if dst not in j['dstIP']:
                        j['dstIP'].append(dst)
                    break
            if flag:
                UA.append({
                    "name": name,
                    "type": type,
                    "stime": time,
                    "etime": time,
                    "info": info,
                    "srcIP": [src],
                    "dstIP": [dst]
                })
    with open("UA.json", 'w') as f:
        json.dump(UA, f)


def writeInnerIP(index):
    innerIP = list()
    for file in index:
        tmp_data = json.load(open("/usr/local/mad" + file, 'r'))
        for i in tmp_data:
            name = i['UA']
            type = i['is_malicious']
            time = i['time']
            info = i['info']
            src = i['srcIP']
            dst = i['dstIP']
            flag = True
            for j in innerIP:
                if src == j['IP']:
                    flag = False
                    flag2 = True
                    for k in j['UA']:
                        if name == k['name'] and type == k['type']:
                            flag2 = False
                            if time < k['stime']:
                                k['stime'] = time
                            elif time > k['etime']:
                                k['etime'] = time
                    if flag2:
                        j["total"] += 1
                        if type == 1:
                            j["malicious"] += 1
                        j['UA'].append({
                            "name": name,
                            "stime": time,
                            "etime": time,
                            "type": type,
                            "info": info
                        })
                    break
            if flag:
                innerIP.append({
                    "IP": src,
                    "total": 1,
                    "malicious": type,
                    "UA": [
                        {
                            "name": name,
                            "stime": time,
                            "etime": time,
                            "type": type,
                            "info": info
                        }]
                })
    with open("innerIP.json", 'w') as f:
        json.dump(innerIP, f)


def writeOuterIP(index):
    outerIP = list()
    for file in index:
        tmp_data = json.load(open("/usr/local/mad" + file, 'r'))
        for i in tmp_data:
            name = i['UA']
            type = i['is_malicious']
            time = i['time']
            info = i['info']
            src = i['srcIP']
            dst = i['dstIP']
            flag = True
            for j in outerIP:
                if dst == j['IP']:
                    flag = False
                    if time < j['stime']:
                        j['stime'] = time
                    elif time > j['etime']:
                        j['etime'] = time
                    flag2 = True
                    for k in j['inner']:
                        if src == k['IP'] and name == k['UA']:
                            if time < k['stime']:
                                k['stime'] = time
                            elif time > k['etime']:
                                k['etime'] = time
                    if flag2:
                        j['inner'].append({
                            "IP": src,
                            "UA": name,
                            "stime": time,
                            "etime": time
                        })
                    break
            if flag:
                outerIP.append({
                    "IP": dst,
                    "type": type,
                    "stime": time,
                    "etime": time,
                    "inner": [{
                        "IP": src,
                        "UA": name,
                        "stime": time,
                        "etime": time
                        }]
                })
    with open("outerIP.json", 'w') as f:
        json.dump(outerIP, f)

if __name__ == "__main__":
    index = readReportList("./Background_PC")
    writeInnerIP(index)
    writeUA(index)
    writeOuterIP(index)
