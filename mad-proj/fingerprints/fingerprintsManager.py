from fingerprints.fingerprint import *
from fingerprints.detection import *
import pickle
import os

class fingerprintManager:
    def __init__(self):
        self.filepath="/usr/local/mad/fingerprint.pickle"
        self.fingerprints={}
        self.detector=DetectionModule()
        if os.path.exists(self.filepath):
            with open(self.filepath,"rb") as f:
                self.fingerprints=pickle.load(f)

    def GenerateAndUpdate(self,sniffedPackets_or_streampath,groups,type):   #type 1 means sniffed subject,2 means pcap files
        Gen=FingerprintGenerator(sniffedPackets,type)
        fingerprints=Gen.genrate(groups)
        self.add_update(fingerprints)
        with open(self.filepath,"w") as f:
            pickle.dump(self.fingerprints,f)
        f.close()


    def Identify(self,sniffedPackets,groups):
        Gen=FingerprintGenerator(sniffedPackets,1)
        fingerprints=Gen.genrate(groups)
        result={"is_malicious":[],"new_app":[]}
        for app in fingerprints:
            flag=False
            for old_app in self.fingerprints:
                if self.detector.similarity_check(fingerprints[app],self.fingerprints[old_app]):
                    flag=True
                    if self.fingerprints[old_app].is_malicious:
                        result["is_malicious"].append(app)
                    break
            if not flag:
                result["new_app"].append(app)
        return result


    def add_update(self,newfingerprints):
        print("Updating fingerprints ......")
        for app in newfingerprints:
            flag=False
            for old_app in self.fingerprints:
                if self.detector.similarity_check(newfingerprints[app],self.fingerprints[old_app]):
                    flag=True
                    break
            if not flag:
                self.fingerprints[app]=newfingerprints[app]

