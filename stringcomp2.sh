#!/bin/bash

a="bac"
b="lkj"

if [ $a = $b ];then
echo " $a and $b are same"
else
echo " $a nd $b are diff"
fi

if [ $a != $b  ]
then
echo " $a is not eq $b "
else
echo " $a is same as $b "
fi 

if [ -z $a  ]
then
echo " string lenght is zero "
else
echo " string lenght is not zero "
fi

if [ -n $a ]
then
echo " string ln is not zero "
else
echo " string ln is zero "
fi

if [ $a ]
then
echo "string is not empty"
else
echo "strnig is empty"
fi
