#!/bin/bash

# set -x

echo '+ ps -aux | grep dataset'
ps -aux | grep dataset ; echo

counts=`python3 -c "for index in range(0, 40): print(str(index).rjust(3, '0'))"`
for index in $counts; do
    echo "+ cat nohup_${index}.out | grep dump | tail"
    cat nohup_${index}.out | grep dump | tail -n 5 ; echo
done

echo '+ cat nohup_cmp.out | grep dump | tail'
cat nohup_cmp.out | grep dump | tail -n 5 ; echo

python3 dataset_index.py
python3 make_index.py
python3 count.py
echo
