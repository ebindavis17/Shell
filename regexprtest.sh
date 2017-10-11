#!/bin/bash

for deb in /ebin/davis/packs/*
do
	pkgname=` basename $deb `
	if [[ $pkgname =~ .*\.deb ]];then
 		echo "$package name is .deb package "
	else
		echo " File "$package" is not a .deb package "
	fi
done

