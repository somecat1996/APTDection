import os
import sys
import subprocess
import time


srcPath = __file__
path = os.path.abspath(srcPath)
path = os.path.split(path)[0]

DataPath = "/home/ubuntu/mkdat/cmp/httpheader/"
ModelPath = "/home/ubuntu/ModelPath/Backgroud_PC_Model_20180515_httpheader/"
mode = "train"
T = "Background_PC"

LogPath = os.path.join(path, "logs")


while 1:
    # t---train
    # r---retrain
    # e---evaluate
    # p---predict
    # s---status
    # md--modify data path
    # mm--modify model path
    # q---quit
    print("Input your command.")
    UserInput = sys.stdin.readline().strip()
    if UserInput == 'md':
        tmp = ''
        while not os.path.isdir(tmp):
            print("Input an exit folder.")
            tmp = sys.stdin.readline().strip()
        DataPath = tmp
    elif UserInput == 'mm':
        print("Input an exit folder.")
        ModelPath = sys.stdin.readline().strip()
    elif UserInput == 's':
        print("Data Path: "+DataPath)
        print("Model Path: "+ModelPath)
        print("Type: "+T)
    elif UserInput == 'q':
        print("quitting")
        sys.exit(0)
    elif UserInput == 't':
        mode = "train"
        log = os.path.join(LogPath, str(int(time.time()))+"train.log")
        command = ["python3", os.path.join(path, "Training.py"), DataPath, ModelPath, mode, T]
        subprocess.run(command)
        # subprocess.run(command,
        #                stdout=open(log, 'wb'))
    elif UserInput == 'r':
        mode = "retrain"
        log = os.path.join(LogPath, str(int(time.time()))+"retrain.log")
        command = ["python3", os.path.join(path, "Training.py"), DataPath, ModelPath, mode, T]
        subprocess.run(command)
        # subprocess.run(command,
        #                stdout=open(log, 'wb'))
    elif UserInput == 'e':
        mode = "evaluate"
        log = os.path.join(LogPath, str(int(time.time()))+"evaluate.log")
        command = ["python3", os.path.join(path, "Training.py"), DataPath, ModelPath, mode, T]
        subprocess.run(command)
        # subprocess.run(command,
        #                stdout=open(log, 'wb'))
        subprocess.run(["cat", log])
    elif UserInput == 'p':
        mode = "predict"
        log = os.path.join(LogPath, str(int(time.time()))+"pretict.log")
        command = ["python3", os.path.join(path, "Training.py"), DataPath, ModelPath, mode, T]
        subprocess.run(command)
        # subprocess.run(command,
        #                stdout=open(log, 'wb'))
    else:
        print("unavailable")
