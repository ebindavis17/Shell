#!/bin/bash

echo " this is $0 "

filename=${1:-/ebin/davis/nz.sh}
x=$(mktemp -p /ebin/davis -t hello.XXXXX)

if [ -r "$filename"  ] && [ -s "$filename" ] || [ -O "$filename"]
then
echo " this is  -- readable -- non zero string and -- owner " > $x
else
echo " something else "
fi
