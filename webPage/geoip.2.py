import ast
import json

geoip = list()
with open('temp.txt') as file:
    for line in file:
        _, ip, latlng = line.strip().split(' ', 2)
        try:
            geoip.append(dict(
                ip=ip, 
                latLng=ast.literal_eval(latlng),
            ))
        except SyntaxError:
            print(ip, latlng)

print(geoip)
with open('server_map.json', 'w') as file:
    json.dump(geoip, file)
