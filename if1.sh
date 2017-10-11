#!/bin/bash
# Test for failure
echo -n "enter no :"
read j
if [ $j -ne 0 ] 
then
echo “Error: Reading $1 failed.”
else 
echo " it is zero "
fi
