#!/bin/sh

# Executable
curdir=`pwd`
#exec="tethereal"
exec="tcpdump"

which ${exec} >& /dev/null
if [ $? != 0 ]; then
  # Try in local directory
  exec="./tethereal"
fi

# Stop writing to a capture file after value seconds have elapsed.
#duration=-a duration:60

# Capture file
capture_file="/tmp/capture.cap"

# Filter (tcpdump format)
filter="' "
filter="$filter !(tcp port 22)"            # SSH
filter="$filter and !(tcp port 3306)"      # MySQL
filter="$filter and !(tcp port 5222)"      # Jabber
filter="$filter and !(udp port 2049)"      # NFS
filter="$filter '"

# Display packet summary while dumping packets
#options=-S

# Don't display the continuous count of packets captured that is normally shown
# when saving a capture to a file; instead, just display, at the end of the capture,
# a count of packets captured.
options="${options} -s 0"  # for tcpdump only. Not for tethereal
options="${options} -q"
options="${duration} ${options}"

eval "${exec} -f ${filter} ${options} -w ${capture_file}"
