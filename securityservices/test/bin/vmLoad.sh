#!/bin/sh
#ps -o pid,user,cutime,utime,size,vsize,cmd -C java
ps -o pid,user,utime,size,vsize,cmd -C java --no-headers | head -n1

