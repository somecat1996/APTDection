# -*- coding: utf-8 -*-

import json
import os

temp = list()
temp.extend(map(lambda name: f'/data/wanyong-httpdump/20180408/20180309/{name}',
                filter(lambda name: '.pcap' in os.path.splitext(name)[1],
                        sorted(os.listdir(f"/data/wanyong-httpdump/20180408/20180309")))))
temp.extend(map(lambda name: f'/data/wanyong-httpdump/20180407/{name}',
                filter(lambda name: '.pcap' in os.path.splitext(name)[1],
                        sorted(os.listdir(f"/data/wanyong-httpdump/20180407")))))
temp.extend(map(lambda name: f'/data/wanyong-httpdump/20180408/{name}',
                filter(lambda name: '.pcap' in os.path.splitext(name)[1],
                        sorted(os.listdir(f"/data/wanyong-httpdump/20180408")))))

with open('./data.json', 'w') as file:
    json.dump(temp, file)

import pprint
pprint.pprint(temp)
