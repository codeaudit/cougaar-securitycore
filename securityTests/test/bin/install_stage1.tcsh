#!/bin/tcsh

set zipFilename = $1

set cipDirPrefix = ~/UL/cougaar

set cdir = `mktemp -d ${cipDirPrefix}.XXXX` 

# Stage 1: Create CIP directory

rm -f ${CIP}

cd $cdir/..
ln -s $cdir cougaar

cd $CIP
mkdir acme-1.6
ln -s acme-1.6 acme

