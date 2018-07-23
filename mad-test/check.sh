#!/bin/bash

grep="grep --color=auto"

FILE="07231340.out"

ps -aux | $grep mad

head -n 1 $FILE

$grep "No\." $FILE | tail | $grep "No\."

# $grep "@" $FILE | tail | $grep "@"

tail $FILE ; echo

$grep "loss\:" $FILE | tail | $grep "loss\:"

$grep Traceback $FILE -c
