from webgraphic import *
from StreamManager3 import *
builder=webgraphic()
builder.read_in("./stream/nice/nice.pcap")
IPS=builder.GetIPS()
print(IPS)
stream=StreamManager("nice.pcap")
stream.generate()
stream.classify(IPS)
stream.LableAndGroup()
typeone=stream.GetBrowserGroup_PC()
typetwo=stream.GetBackgroudGroup_PC()
typethree=stream.GetBrowserGroup_Phone()
typefour=stream.GetBackgroudGroup_Phone()
typefive=stream.GetSuspicious()

print("种类1恶意---------------------------------------")
for key in typeone:
    for x in typeone[key]:
        if x["malicious"]!=0 or x["suspicious"]!=0:
            print(key,typeone[key])

print("种类2恶意---------------------------------------")
for key in typetwo:
    for x in typetwo[key]:
        if x["malicious"]!=0 or x["suspicious"]!=0:
            print(key,typetwo[key])

print("种类3恶意---------------------------------------")
for key in typethree:
    for x in typethree[key]:
        if x["malicious"]!=0 or x["suspicious"]!=0:
            print(key,typethree[key])

print("种类4恶意---------------------------------------")
for key in typefour:
    for x in typefour[key]:
        if x["malicious"]!=0 or x["suspicious"]!=0:
            print(key,typefour[key])

print("种类5恶意---------------------------------------")
for key in typefive:
    for x in typefive[key]:
        if x["malicious"]!=0 or x["suspicious"]!=0:
            print(key,typefive[key])