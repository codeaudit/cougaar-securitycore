#!/bin/sh

exec="tethereal"

# Capture file
capture_file=$1
eval "rm -f $1"
shift
# Filter (tcpdump format)
filter="' "
filter="$filter !(tcp port 22)"            # SSH
filter="$filter and !(tcp port 3306)"      # MySQL
filter="$filter and !(tcp port 5222)"      # Jabber
n=$#
while [ $# -ge 1 ]
do
     filter="$filter and not host $1"
     shift
done
filter="$filter '"

# Don't display the continuous count of packets captured that is normally shown
# when saving a capture to a file; instead, just display, at the end of the capture,
# a count of packets captured.
#options="${options} -s 0"  # for tcpdump only. Not for tethereal
options="${options} -q"
options="${options} -o ip.defragment:TRUE"
options="${duration} ${options}"
                                                                                
echo "sudo ${excec} -f ${filter} ${options} -w ${capture_file}"  
eval "sudo ${exec} -f ${filter} ${options} -w ${capture_file} &"
echo "$!" > .tethereal.pid
