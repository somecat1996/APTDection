import os
import json


Input = "pkt2flow/stream/"
Output = "check.json"

dirs = [x for x in os.listdir(Input) if os.path.isdir(Input + x)]
print(dirs)
tmp = {}
for i in dirs:
    try:
        files = json.load(open(Input + i+'/stream.json', 'r'))
        for j in files['Backgroud_PC']:
            for k in files['Backgroud_PC'][j]:
                if k['malicious'] > 0 or k['suspicious'] > 0:
                    tmp[k['filename'][:-5]] = [k['malicious'], k['suspicious']]
    except:
        pass
print(tmp)
json.dump(tmp,open(Output, 'w'))
