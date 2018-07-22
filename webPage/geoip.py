# -*- coding: utf-8 -*-


import json
import os

import geocoder


with open('/usr/local/mad/report/Background_PC/index.json') as file:
    filelist = json.load(file)

geoip = list()
for filename in filelist:
    with open(filename) as file:
        report = json.load(file)
    for item in report:
        if not item['is_malicious']:    continue
        ip = item['dstIP']
        latlng = geocoder.ip(ip).latlng
        geoip.append(dict(
            name=ip,
            latLng=latlng,
        ))

with open('/usr/local/mad/report/server_map.json') as file:
    json.dump(geoip, file)
