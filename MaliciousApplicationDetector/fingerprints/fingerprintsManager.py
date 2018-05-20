from fingerprints.fingerprint import *
from fingerprints.detection import *
import pickle
import os


srcPath = __file__
path = os.path.abspath(srcPath)
path = os.path.split(path)[0]


class fingerprintManager:
    def __init__(self):
        self.filepath = os.path.join(path, "fingerprints")
        self.fingerprints = {}
        self.detector = DetectionModule()
        if os.path.exists(self.filepath):
            with open(self.filepath, "r") as f:
                self.fingerprints = pickle.load(f)

    def GenerateAndUpdate(self, stream_path, groups):
        Gen = FingerprintGenerator(stream_path)
        fingerprints = Gen.genrate(groups)
        self.add_update(fingerprints)
        with open(self.filepath, "w") as f:
            pickle.dump(self.fingerprints, f)
        f.close()

    def Identify(self, stream_path, groups):
        Gen = FingerprintGenerator(stream_path)
        fingerprints = Gen.genrate(groups)
        result = {"is_malicious": [], "new_app": []}
        for app in fingerprints:
            flag = False
            for old_app in self.fingerprints:
                if self.detector.similarity_check(fingerprints[app], self.fingerprints[old_app]):
                    flag = True
                    if self.fingerprints[old_app].is_malicious:
                        result["is_malicious"].append(app)
                    break
            if not flag:
                result["new_app"].append(app)
        return result

    def add_update(self, newfingerprints):
        print("Updating fingerprints ......")
        for app in newfingerprints:
            flag = False
            for old_app in self.fingerprints:
                if self.detector.similarity_check(newfingerprints[app], self.fingerprints[old_app]):
                    flag = True
                    break
            if not flag:
                self.fingerprints[app] = newfingerprints[app]