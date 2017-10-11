#!/bin/bash

package=dbus-x11_1.2.24-4_amd64.deb

if [[ $package =~ .*\.deb ]]; then
#if [[ $package =~ (.+)_(.*)_(.*)\.deb ]]
	echo " Package ${BATCH_MATCH[1]} Version ${BATCH_MATCH[2]} "\
	     "is for the "${BATCH_MATCH[3]}" architecture "
	
	else
	echo " File \"$package\" doesnot excits"
fi
