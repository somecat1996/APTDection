import os
import sys
import subprocess
import getopt

srcPath = __file__
path = os.path.abspath(srcPath)
path = os.path.split(path)[0]

DataPath = ''
ModelPath = ''
Mode = ''
T = "Background_PC"

options, args = getopt.getopt(sys.argv[1:], "trped:m:",
                              ["train", "retrain", "predict", "evaluate", "datapath=", "modelpath="])

for name, value in options:
    if name in ("-t", "--train"):
        Mode = "train"
    if name in ("-r", "--retrain"):
        Mode = "retrain"
    if name in ("-p", "--predict"):
        Mode = "predict"
    if name in ("-e", "--evaluate"):
        Mode = "evaluate"
    if name in ("-d", "--datapath"):
        DataPath = value
    if name in ("-m", "--modelpath"):
        ModelPath = value

if not Mode:
    print("Unavailable operating mode. ")
    exit(1)

with open(os.path.join(path, "default"), "r") as default:
    defaultModel = default.readline().strip()
    defaultData = default.readline().strip()

ModelPath = ModelPath or defaultModel
DataPath = DataPath or defaultData

with open(os.path.join(path, "default"), "w") as default:
    default.writelines([ModelPath+'\n', DataPath])

command = ["python3", os.path.join(path, "Training.py"), DataPath, ModelPath, Mode, T]
subprocess.run(command)
# LogPath = os.path.join(path, "logs")
# log = os.path.join(LogPath, str(int(time.time())) + "-" + Mode + ".log")
# subprocess.run(command,
#                stdout=open(log, 'wb'))
