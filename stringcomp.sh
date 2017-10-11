#!/bin/bash
a="abc"
b="ssabc"
if [ "$a" = "$b" ]
then
echo " $a is same as $b "
else
echo " are diff"
fi

if [ $a != $b ]
then
echo "they are diff"
else
echo "same"
fi
