#!/bin/bash

filename=${1:-/ebin/davis/if.sh}
if [ -r “$filename” ]
then 
cat $filename
else
echo " file is not readable"
fi
