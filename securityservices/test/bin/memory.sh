#!/bin/sh

rm topOut
while true; do
$CIP/operator/runallparallel 'top -b -n 1 | grep java | sort &' | tee -a topOut
date | tee -a topOut
sleep 10
done
