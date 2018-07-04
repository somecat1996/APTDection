# PyPCAPKit

我把原来的 `jspcap` 重构了一下，然后更名为 `pypcapkit`。并且新增了一些功能：

 - 支持使用 `Scapy` 解析数据包，解析后的 `Packet` 也原样保存
 - 融合了 `pkt2flow` 追踪 TCP 流量的功能，能够导出 PCAP 格式的文件
 - 大概就这样……

所以我们目前就可以把之前 `DataLabeler`、`WebGraphic` 和 `fingerprints` 以及最后 `dataset` 中把同一个流量包反复解析的问题解决掉。首先用 `pkt2flow` 将原始 PCAP 文件转换成 TCP 流；随后，对每一个 TCP 流的 PCAP 文件，使用 `pypcapkit` 的 `Scapy` 引擎解析，可得到 `Packet` 对象的列表，以及重组后的应用层数据，我们可以直接把这些数据直接传递，就避免重复解析同一个文件了。

示例如下：

```python
>>> import pprint
>>> from pcakit.all import *
>>> pcap = extract(
			fin='in.cap',				# input file name
			nofile=True,				# no output file for extraction
			engine=Scapy,				# use Scapy as extraction engine
			tcp=True,					# do TCP reassembly
			store=True,					# store extracted packet (list of Scapy Packet objects)
			strict=True,				# do reassembly in strict mode
			extension=False,			# no extension auto-complete
	)
>>> pcap
<pcapkit.foundation.extraction.Extractor object at 0x104b91f60>
>>> type(pcap.frame[0])
<class 'scapy.layers.l2.Ether'>
>>> pprint.pprint(pcap.frame) 			# extracted packet
(<Ether  dst=40:33:1a:d1:85:1c src=a4:5e:60:d9:6b:97 type=0x86dd |<IPv6  version=6 tc=0 fl=0 plen=32 nh=ICMPv6 hlim=255 src=fe80::a6:87f9:2793:16ee dst=fe80::1ccd:7c77:bac7:46b7 |<ICMPv6ND_NS  type=Neighbor Solicitation code=0 cksum=0xeaa res=0 tgt=fe80::1ccd:7c77:bac7:46b7 |<ICMPv6NDOptSrcLLAddr  type=1 len=1 lladdr=a4:5e:60:d9:6b:97 |>>>>,
 <Ether  dst=a4:5e:60:d9:6b:97 src=40:33:1a:d1:85:1c type=0x86dd |<IPv6  version=6 tc=0 fl=0 plen=24 nh=ICMPv6 hlim=255 src=fe80::1ccd:7c77:bac7:46b7 dst=fe80::a6:87f9:2793:16ee |<ICMPv6ND_NA  type=Neighbor Advertisement code=0 cksum=0x3f82 R=0 S=1 O=0 res=0x0 tgt=fe80::1ccd:7c77:bac7:46b7 |>>>,
 <Ether  dst=a4:5e:60:d9:6b:97 src=b8:f8:83:a5:f9:47 type=0x800 |<IP  version=4 ihl=5 tos=0x0 len=40 id=50484 flags=DF frag=0 ttl=43 proto=tcp chksum=0x7a86 src=123.129.210.135 dst=192.168.1.100 options=[] |<TCP  sport=http dport=55232 seq=3584012628 ack=2793054463 dataofs=5 reserved=0 flags=FA window=31920 chksum=0x7c8e urgptr=0 |>>>,
 <Ether  dst=b8:f8:83:a5:f9:47 src=a4:5e:60:d9:6b:97 type=0x800 |<IP  version=4 ihl=5 tos=0x0 len=40 id=0 flags=DF frag=0 ttl=64 proto=tcp chksum=0x2abb src=192.168.1.100 dst=123.129.210.135 options=[] |<TCP  sport=55232 dport=http seq=2793054463 ack=3584012629 dataofs=5 reserved=0 flags=A window=65535 chksum=0xf93e urgptr=0 |>>>,
 <Ether  dst=b8:f8:83:a5:f9:47 src=a4:5e:60:d9:6b:97 type=0x800 |<IP  version=4 ihl=5 tos=0x0 len=40 id=0 flags=DF frag=0 ttl=64 proto=tcp chksum=0x2abb src=192.168.1.100 dst=123.129.210.135 options=[] |<TCP  sport=55216 dport=http seq=768904481 ack=1835365486 dataofs=5 reserved=0 flags=FA window=65535 chksum=0x2af4 urgptr=0 |>>>,
 <Ether  dst=ff:ff:ff:ff:ff:ff src=b8:f8:83:a5:f9:47 type=0x800 |<IP  version=4 ihl=5 tos=0x0 len=145 id=0 flags=DF frag=0 ttl=64 proto=udp chksum=0x78b3 src=192.168.1.1 dst=255.255.255.255 options=[] |<UDP  sport=37444 dport=commplex_link len=125 chksum=0x63b1 |<Raw  load='\x01\x01\x0e\x00\xe1+\x83\xc7\xf9\x8b\x00g\x00\x00\x00\x06\x00\nTL-WDR6300\x00\x0b\x00\x036.0\x00\x07\x00\x01\x01\x00\x05\x00\x11B8-F8-83-A5-F9-47\x00\x08\x00\x0b192.168.1.1\x00\t\x00\ntplogin.cn\x00\n\x00\x0eTL-WDR6300 6.0\x00\x0c\x00\x051.7.4' |>>>>)
```
