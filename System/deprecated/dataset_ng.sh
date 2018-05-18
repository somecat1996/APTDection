#!/bin/bash

nohup /home/linuxbrew/.linuxbrew/bin/python3 dataset_label.py >> nohup_label.out &

counts=`python -c "for index in range(3, 21): print(str(index).rjust(3, '0'))"`
for index in $counts; do
    while [ ! -e "./dataset/wanyong80_${index}/stream.json" ] ; do
        echo "File ./dataset/wanyong80_${index}/stream.json not found & keep waiting"
        sleep 600
    done
    sleep 60
    echo "Found ./dataset/wanyong80_${index}/stream.json & now to dump files"
    nohup /home/linuxbrew/.linuxbrew/bin/python3 dataset_json.py "wanyong80_${index}.pcap" >> "nohup_${index}.out" &
done

counts=`python -c "for index in range(31, 40): print(str(index).rjust(3, '0'))"`
for index in $counts; do
    while [ ! -e "./dataset/wanyong80_${index}/stream.json" ] ; do
        echo "File ./dataset/wanyong80_${index}/stream.json not found & keep waiting"
        sleep 600
    done
    sleep 60
    echo "Found ./dataset/wanyong80_${index}/stream.json & now to dump files"
    nohup /home/linuxbrew/.linuxbrew/bin/python3 dataset_json.py "wanyong80_${index}.pcap" >> "nohup_${index}.out" &
done
