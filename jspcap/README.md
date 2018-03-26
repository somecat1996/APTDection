# JSPCAP

&emsp; &emsp; 这是一个用 __Python 3.6__ 编写的 PCAP 文件解析库。目前，在 HTTP 协议族下，可分析 **`Ethernet:[802.1Q:]IPv4:TCP:HTTP/1.*`** 协议链。由于 TLS/SSL 协议族与 HTTP/2 协议的相似度，暂未将后者的解析载入运行逻辑；如能够确认文件中不存在 TLS/SSL 协议族，则可将此载入。

### 安装

```shell
# 从 PyPI 下载
pip[3] install jspcap

# 从 TestPyPI 下载最新版本
list=`pip[3] install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple -I jspcap==newest 2>&1 | grep "from versions: " | sed "s/.*(from versions: \(.*\)*)/\1/"`
IFS=', ' read -ra array <<< "$list"
length=$[${#array[@]} - 1]
newest=${array[$length]}
sudo pip[3] install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple -I jspcap==$newest --upgrade --no-cache-dir

# 从 GitHub 直接获取
git clone https://github.com/JarryShaw/jspcap.git
python[3] setup.py install
```

### 使用

```python
import jspcap

test = jspcap.Extractor(fin='in.pcap', nofile=True, auto=False)

for frame in extractor:
    # check if this frame contains HTTP
    if 'HTTP/1.0' in frame:
        flag = 'HTTP/1.0'
    elif 'HTTP/1.1' in frame:
        flag = 'HTTP/1.1'
    else:
        flag = None

    if flag:
        # print frame number & its protocols chain
        print(f'{frame.name}: {frame.protochain}')

        # fetch http info dict
        # http = dict(
        #     receipt = 'request' | 'response',
        #     # request header
        #     request = dict(
        #         method = METHOD,
        #         target = TARGET,
        #         version = '1,0' | '1.1',
        #     )
        #     # response header
        #     response = dict(
        #         version = '1,0' | '1.1',
        #         status = STATUS,
        #         phrase = PHRASE,
        #     )
        #     # other fields
        #     ...
        # )
        http = frame[flag]

        # fetch HTTP type (request/response)
        http_type = http.receipt    # or http['receipt']

        # fetch HTTP header fields dict
        http_header = http.header   # or http['header']

        # fetch HTTP body
        http_body = http.body       # or http['body']

        # or do something else
        ...
```
