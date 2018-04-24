import requests
import os
import time
import urllib.parse
import urllib.request


class virustotal:
    def __init__(self):
        self.apikey = "5d3e083f2df618e805d4e181c9b17bf83b1d4c5abd71bacd57b6713dca71d95c"

    def label(self, urls):
        scan_id = self.PostAndScan(urls)
        return self.GetReport(scan_id)

    def PostAndScan(self, urls):
        url = 'https://www.virustotal.com/vtapi/v2/url/scan'

        params = {'apikey': self.apikey, 'url': urls}

        response = requests.post(url, data=params)

        # print(response.json())
        return response.json()["scan_id"]

    def GetReport(self, scan_id):
        url = 'https://www.virustotal.com/vtapi/v2/url/report'

        params = {'apikey': self.apikey, 'resource': scan_id, 'allinfo': True}

        response = requests.get(url, params=params)
        # print(response.json())
        print(response.json()['positives'], "个工具检测为positive")
        if response.json()['positives'] > 1:
            return 1
        else:
            return 0


if __name__ == '__main__':
    scanner = virustotal()
    urls = ["https://blog.csdn.net/u010459100/article/details/44238599",
            "https://zhidao.baidu.com/question/1431279871222200339.html",
            "109.234.36.233"]
    for x in urls:
        label = scanner.lablel(x)
        time.sleep(15)
        print(label)

'''
import hashlib

m2 = hashlib.md5()
m2.update(src)
print(m2.hexdigest())
'''
