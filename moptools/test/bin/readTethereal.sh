#!/bin/sh
rm -f $2
sudo tethereal -z io,phs -o ip.defragment:TRUE -r $1 >> $2
