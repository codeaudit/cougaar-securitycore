#!/bin/sh

rm topOut
while true; do
#$CIP/operator/runallparallel 'ps -o pid,user,utime,size,vsize,cmd -C java --no-headers' | tee -a topOut
#$CIP/operator/runallparallel 'top -b -n 1 | grep java | sort' | tee -a topOut
$CIP/operator/runallparallel '${CIP}/operator/printProcessInfo.rb' | tee -a topOut

date | tee -a topOut
sleep 10
done
