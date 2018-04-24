import requests
import os
import time

class virustotal:
    def __init__(self):
        self.apikey="5d3e083f2df618e805d4e181c9b17bf83b1d4c5abd71bacd57b6713dca71d95c"

    def lable(self,filepath):
        md5=self.PostAndScan(filepath)
        return self.GetReport(md5)

    def PostAndScan(self,filepath):

        filename=os.path.basename(filepath)
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey':self.apikey}
        files = {'file': (filename, open(filepath, 'rb'))}
        response = requests.post(url, files=files, params=params)
        return response.json()['md5']


    def GetReport(self,md5):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'

        params = {'apikey': self.apikey, 'resource': 'f9f608407d551f49d632bd6bd5bd7a56','allinfo':True}

        response = requests.get(url, params=params)
        print(response.json())

        if response.json()['positives']>1:
            return 1
        else:
            return 0

if __name__=='__main__':
    scanner=virustotal()
    files=["C:\\Users\\Rea\\PycharmProjects\\VirusLable\\hello.php","C:\\Users\\Rea\\PycharmProjects\\VirusLable\\testrun.py",
           "C:\\Users\\Rea\\PycharmProjects\\VirusLable\\webgraphic.py","C:\\Users\\Rea\\PycharmProjects\\VirusLable\\group.py"]
    for x in files:
        md5=scanner.PostAndScan(x)
        print(md5)
        scanner.GetReport(md5)
        time.sleep(10)

'''
import hashlib

m2 = hashlib.md5()
m2.update(src)
print(m2.hexdigest())
'''