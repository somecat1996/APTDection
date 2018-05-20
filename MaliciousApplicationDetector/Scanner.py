import os
import sys
import subprocess


srcPath = sys.argv[0]
path = os.path.abspath(srcPath)
path = os.path.split(path)[0]

DataPath = "/home/ubuntu/mkdat/cmp/httpheader/"
ModelPath = "/home/ubuntu/ModelPath/Backgroud_PC_Model_20180515_httpheader/"
mode = "train"
T = "Background_PC"


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
        # tf.app.run()
    elif UserInput == 'r':
        mode = "retrain"
        # tf.app.run()
    elif UserInput == 'e':
        mode = "evaluate"
        print(path)
        # subprocess.run(["python3", path+"Training.py", DataPath, ModelPath, mode, T])
        # tf.app.run()
    elif UserInput == 'p':
        mode = "pretict"
        # tf.app.run()
    else:
        print("unavailable")
