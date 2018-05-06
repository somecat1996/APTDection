.
|-- file.pcap
|-- stream
|		|-- file
|		|	|-- file.pcap
|		|	|-- tmp
|		|	 		|-- file_stream.pcap
|		|	 		|-- ...
|		|-- ...
|-- dataset
|		|-- file
|		|	|-- Group0
|		|	|		|-- 1(bad)
|		|	|		|	|-- file_stream.dat
|		|	|		|	|-- ...
|		|	|		|-- 0(good)
|		|	|			|-- file_stream.dat
|		|	|			|-- ...
|		|	|-- ...
|		|-- ...
|-- ...



{
	"ip+ua" : [
		"filename" : {
			malicious : int(count),
			suspicious : int(count),
		},
		...
	],
	...
}
