#!/bin/sh
sudo kill -INT `cat .tethereal.pid`
rm -f .tethreal.pid