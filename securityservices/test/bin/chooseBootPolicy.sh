#!/bin/sh

naiaddr=`/sbin/ifconfig eth0 | /bin/egrep 'addr:161.69.57.|addr:162.10.1.'`

if [ "$naiaddr" == "" ] ; then
    mv $1/BootPolicy.UserDB.TIC.xml $1/BootPolicy.UserDB.xml
fi
