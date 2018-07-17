from webgraphic.webgraphic import *
from StreamManager.StreamManager4 import *
from fingerprints.fingerprintsManager import fingerprintManager
import time
start=time.time()
builder=webgraphic()
builder.read_in("./stream/wanyong80/wanyong80.pcap")
IPS=builder.GetIPS()
#print(IPS)
print("-------------------------------------------------------")
stream=StreamManager("wanyong80.pcap")
stream.generate()
stream.classify(IPS)
stream.Group()
#stream.labelGroups()
#typeone=stream.GetBrowserGroup_PC()
typetwo=stream.GetBackgroudGroup_PC()
#typethree=stream.GetBrowserGroup_Phone()
typefour=stream.GetBackgroudGroup_Phone()
typefive=stream.GetSuspicious()
#group=stream.GetDataForCNN()
'''
print("种类1恶意---------------------------------------")
for key in typeone:
    for x in typeone[key]:
        if x["is_malicious"]!=0 :
            print(key,typeone[key])
            break
            
print("种类2恶意---------------------------------------")
for key in typetwo:
    for x in typetwo[key]:
        if x["is_malicious"]!=0 :
            print(key,typetwo[key])
            break

print("种类3恶意---------------------------------------")
for key in typethree:
    for x in typethree[key]:
        if x["is_malicious"]!=0 :
            print(key,typethree[key])
            break;

print("种类4恶意---------------------------------------")
for key in typefour:
    for x in typefour[key]:
        if x["is_malicious"]!=0 :
            print(key,typefour[key])
            break
print("种类5恶意---------------------------------------")
for key in typefive:
    for x in typefive[key]:
        if x["is_malicious"]!=0 :
            print(key,typefive[key])
            break
'''
finger=fingerprintManager()
print("生成指纹2....")
#finger.GenerateAndUpdate("./stream/wanyong80/tmp",typetwo)
r=finger.Identify("./stream/wanyong80/tmp",typetwo)
print("生成指纹4....")
#finger.GenerateAndUpdate("./stream/wanyong80/tmp",typefour)
r=finger.Identify("./stream/wanyong80/tmp",typefour)
print("生成指纹5....")
#finger.GenerateAndUpdate("./stream/wanyong80/tmp",typefive)
r=finger.Identify("./stream/wanyong80/tmp",typefive)
end=time.time()

print("总耗时 ： ",end-start," s")
