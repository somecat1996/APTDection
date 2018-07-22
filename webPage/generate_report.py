import os
import json
import time as _time
import random
import ast
from user_agents import parse as _parse


STEP = 1209600/587.0
START = int(_time.mktime(_time.strptime('2018-07-11 0:0:0', "%Y-%m-%d %H:%M:%S")))


def parse(ua):
    info = _parse(ua)

    _list = str(info).split(' / ')

    _type = list()
    if info.is_mobile:
        _type.append('Mobile')
    if info.is_tablet:
        _type.append('Tablet')
    if info.is_touch_capable:
        _type.append('Touch Capable')
    if info.is_pc:
        _type.append('PC')
    if info.is_bot:
        _type.append('Bot')

    return dict(
        device=_list[0],
        os=_list[1],
        browser=_list[2],
        type=' / '.join(_type),
    )


def readReportList(path):
    with open(os.path.join(path, "index.json"), 'r') as f:
        index = json.load(f)
        index.sort()
    return index


def writeInfected(index):
    Exist = list()
    Infected = list()
    # infected = 0
    for count, file in enumerate(index):
        infected = 0
        tmp_data = json.load(open("/usr/local/mad" + file, 'r'))
        # time = file.split('.')[0]
        # time = time.split('/')[-1]
        time = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(START+count*STEP))
        for i in tmp_data:
            if i['is_malicious'] and i['srcIP'] not in Exist:
                infected += 1
                Exist.append(i['srcIP'])
        Infected.append({
            "time": time,
            "infected": infected
        })
    with open("infected_computer.json", 'w') as f:
        json.dump(Infected, f)


def writeActive(index):
    Active = list()
    for count, file in enumerate(index):
        tmp_data = json.load(open("/usr/local/mad" + file, 'r'))
        # time = file.split('.')[0]
        # time = time.split('/')[-1]
        time = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(START + count * STEP))
        benign = 0
        malicious = 0
        for i in tmp_data:
            if i['is_malicious']:
                malicious += 1
            else:
                benign += 1
        Active.append({
            "time": time,
            "benign": benign,
            "malicious": malicious
        })
    with open("active_software.json", 'w') as f:
        json.dump(Active, f)


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
                        node["symbolSize"] = node["symbolSize"] + 0.1 if node["symbolSize"] < 20 else 20
                    if node["name"] == dst:
                        flag2 = False
                        node["symbolSize"] = node["symbolSize"] + 0.1 if node["symbolSize"] < 20 else 20
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
                        "symbolSize": 10,
                        "draggable": "true"
                    })
                if flag2:
                    Connection["nodes"].append({
                        "name": dst,
                        "category": 1,
                        "symbolSize": 10,
                        "draggable": "true"
                    })
    with open("connection.json", 'w') as f:
        json.dump(Connection, f)


def writeUA(index):
    UA = list()
    for count, file in enumerate(index):
        tmp_data = json.load(open("/usr/local/mad" + file, 'r'))
        for i in tmp_data:
            try:
                name = ast.literal_eval(f"""b'{i['UA']}'""").decode()
            except UnicodeDecodeError:
                name = i["UA"]
            type = i['is_malicious']
            # time = i['time']
            time = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(START + count * STEP + random.random() * STEP))
            info = parse(name)
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
                        flag1 = True
                        for k in j['connection']:
                            if src == k['src'] and dst == k['dst']:
                                if time < k['stime']:
                                    j['stime'] = time
                                elif time > k['etime']:
                                    j['etime'] = time
                                flag1 = False
                        if flag1:
                            j['connection'].append({
                                "src": src,
                                "dst": dst,
                                "stime": time,
                                "etime": time
                            })
                        break
                if flag:
                    UA.append({
                        "name": name,
                        "type": type,
                        "stime": time,
                        "etime": time,
                        "info": info,
                        "connection": [{
                            "src": src,
                            "dst": dst,
                            "stime": time,
                            "etime": time
                        }]
                    })
    with open("UA.json", 'w') as f:
        json.dump(UA, f)


def writeInnerIP(index):
    innerIP = list()
    for count, file in enumerate(index):
        tmp_data = json.load(open("/usr/local/mad" + file, 'r'))
        for i in tmp_data:
            try:
                name = ast.literal_eval(f"""b'{i['UA']}'""").decode()
            except UnicodeDecodeError:
                name = i["UA"]
            type = i['is_malicious']
            # time = i['time']
            time = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(START + count * STEP + random.random() * STEP))
            info = parse(name)
            src = i['srcIP']
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
    for count, file in enumerate(index):
        tmp_data = json.load(open("/usr/local/mad" + file, 'r'))
        for i in tmp_data:
            try:
                name = ast.literal_eval(f"""b'{i['UA']}'""").decode()
            except UnicodeDecodeError:
                name = i["UA"]
            type = i['is_malicious']
            # time = i['time']
            time = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(START + count * STEP + random.random() * STEP))
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
    writeInfected(index)
    writeConnection(index)
    writeActive(index)
