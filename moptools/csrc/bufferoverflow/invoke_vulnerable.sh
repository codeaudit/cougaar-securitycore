#!/bin/sh

export EGG=$2
./vulnerable "$1" < $3
