#!/bin/bash
if [ -e /ebin/davis/shiftwhile.sh ]; then
echo “shell shift”
cat /ebin/davis/shiftwhile.sh
else
echo “No DNS resolv.conf file exists.”
fi
