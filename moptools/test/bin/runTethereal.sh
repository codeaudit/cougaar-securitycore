#!/bin/sh
rm -f $1
sudo tethereal -i eth0 -w $1 & echo $! > .tethereal.pid