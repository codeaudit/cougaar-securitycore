#!/bin/sh

pid=`cat .tethereal.pid`
echo "$pid"
kill=`sudo kill $pid`
eval "rm -f .tethereal.pid"
