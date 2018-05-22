import re

file = open("C:/Users/lenovo/Downloads/Backgroud_PC_Model_20180515_httpheader.log", 'r')
text = file.read()
matches = re.findall("{'accuracy': ([\.\d]*), 'loss': ([\.\d]*), 'global_step': ([\.\d]*)}", text)
outfile = open("C:/Users/lenovo/Downloads/Backgroud_PC_Model_20180515_httpheader.txt", 'w')
for i in matches:
    outfile.write(i[0]+' '+i[1]+' '+i[2]+'\n')
