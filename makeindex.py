import os
import json


path = "/home/ubuntu/dataset/"
paths = [os.path.join(path, x) for x in os.listdir(path) if os.path.isdir(path + x)]
print(paths)
for i in paths:
    tmp_dict = {}
    folders = [x for x in os.listdir(i) if os.path.isdir(os.path.join(i, x))]
    print(folders)
    for j in folders:
        tmp_path = os.path.join(i, j)
        tmp_dict[j] = {}
        tmp_dict[j][0] = [os.path.join(tmp_path, '0/'+x) for x in os.listdir(os.path.join(tmp_path, '0/'))]
        tmp_dict[j][1] = [os.path.join(tmp_path, '1/'+x) for x in os.listdir(os.path.join(tmp_path, '1/'))]
    with open(os.path.join(i, "index.json"), "w") as f:
        json.dump(tmp_dict, f)
