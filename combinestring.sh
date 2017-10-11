#!/bin/bash

filename=${1:-/ebin/davis/nz.sh}
or
filename="/ebin/davis/nz.sh"

if [ -f $filename ]
then
echo "file exists "

if [ -r "$filename" ] || [ -s "$filename" ]
or
if [ -r "$filename" ] && [ -s "$filename" ]


then
echo " these are readable and string length is not zero "
else 
echo " cannnot readable "
fi

else 
echo " file doesnot exists "
fi

#if the file is not readable, the -s test will not be executed
