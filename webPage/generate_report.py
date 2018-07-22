import os
import json


def readReportList(path):
    with open(os.path.join(path, "index.json"), 'r') as f:
        index = json.load(f)
        index.sort()
    return index


def writeInfected(index):
    Infected = list()
    infected = 0
    for file in index:
        tmp_data = json.load(open("/usr/local/mad" + file, 'r'))
        time = file.split('.')[0]
        for i in tmp_data:
            if i['is_malicious']:
                infected += 1
        Infected.append({
            "time": time,
            "infected": infected
        })
    with open("infected_computer.json", 'w') as f:
        json.dump(Infected, f)


def writeConnection(index):
    Connection = {
        "nodes": [],
        "links": []
    }
    for file in index:
        tmp_data = json.load(open("/usr/local/mad" + file, 'r'))
        for i in tmp_data:
            src = i['srcIP']
            dst = i['dstIP']
            if i['is_malicious']:
                flag = True
                flag1 = True
                flag2 = True
                for link in Connection["links"]:
                    if link["source"] == src and link["target"] == dst:
                        link["value"] += 1
                        flag = False
                for node in Connection["nodes"]:
                    if node["name"] == src:
                        flag1 = False
                        node["symbolSize"] = node["symbolSize"] + 1 if node["symbolSize"] < 50 else 50
                    if node["name"] == dst:
                        flag2 = False
                        node["symbolSize"] = node["symbolSize"] + 1 if node["symbolSize"] < 50 else 50
                if flag:
                    Connection["links"].append({
                        "source": src,
                        "target": dst,
                        "value": 1
                    })
                if flag1:
                    Connection["nodes"].append({
                        "name": src,
                        "category": 0,
                        "symbolSize": 1,
                        "draggable": "true"
                    })
                if flag2:
                    Connection["nodes"].append({
                        "name": dst,
                        "category": 1,
                        "symbolSize": 1,
                        "draggable": "true"
                    })
    with open("connection.json", 'w') as f:
        json.dump(Connection, f)


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
            if type:
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
            if type:
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
                            }
                        ]
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
            if type:
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
