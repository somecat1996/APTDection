# PyPCAPKit

我把原来的 `jspcap` 重构了一下，然后更名为 `pypcapkit`。并且新增了一些功能：

 - 支持使用 `Scapy` 解析数据包，解析后的 `Packet` 也原样保存
 - 融合了 `pkt2flow` 追踪 TCP 流量的功能，能够导出 PCAP 格式的文件
 - 大概就这样……

所以我们目前就可以把之前 `DataLabeler`、`WebGraphic` 和 `fingerprints` 以及最后 `dataset` 中把同一个流量包反复解析的问题解决掉。首先用 `pkt2flow` 将原始 PCAP 文件转换成 TCP 流；随后，对每一个 TCP 流的 PCAP 文件，使用 `pypcapkit` 的 `Scapy` 引擎解析，可得到 `Packet` 对象的列表，以及重组后的应用层数据，我们可以直接把这些数据直接传递，就避免重复解析同一个文件了。
