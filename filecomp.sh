#!/bin/bash
file1=$1
file2=$1

if [ file1 -ef file2 ]
then
echo " file1 is same as file2"
else
echo " files are different "
diff -q $file1 $file2
if [ $? -eq 0 ]; then
echo “However, their contents are identical.”
fi
fi

