#!/bin/sh

# Executable
curdir=`pwd`
exec="tethereal"

which ${exec} >& /dev/null
if [ $? != 0 ]; then
  # Try in local directory
  exec="./tethereal"
fi

# Stop writing to a capture file after value seconds have elapsed.
#duration=-a duration:60

# Capture file
capture_file="/tmp/capture.cap"

# Filter
filter="'!(tcp port 22)'"

# Display packet summary while dumping packets
#options=-S

# Don't display the continuous count of packets captured that is normally shown
# when saving a capture to a file; instead, just display, at the end of the capture,
# a count of packets captured.
options="${options} -q"
options="${duration} ${options}"

eval "${exec} -f ${filter} ${options} -w ${capture_file}"
