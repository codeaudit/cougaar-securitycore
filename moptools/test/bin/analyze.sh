#!/bin/sh

# Executable
curdir=`pwd`
exec="tethereal"

which ${exec} >& /dev/null
if [ $? != 0 ]; then
  # Try in local directory
  exec="./tethereal"
fi

# Capture file
capture_file="/tmp/capture.cap"

# Display packet summary while dumping packets
#options=-S

# Don't display the continuous count of packets captured that is normally shown
# when saving a capture to a file; instead, just display, at the end of the capture,
# a count of packets captured.
options="${options} -q"

alloptions=" ${options} -r ${capture_file}"

# Display statistics.
# Create Protocol Hierarchy Statistics listing both number of frames and bytes.
eval "${exec} ${alloptions} -z io,phs"

# Create a table that lists all conversations that could be seen in the capture.
#${exec} ${alloptions} -z io,users,tcpip
