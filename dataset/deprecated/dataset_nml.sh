#!/bin/bash

counts=`python3 -c "for index in __import__('random').choices(range(0, 39), k=10): print(str(index).rjust(3, '0'))"`
for index in $counts; do
    nohup python3 dataset.py "wanyong80_${index}.pcap" >> "nohup_${index}.out" &
done
