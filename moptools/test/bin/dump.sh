#!/bin/sh

# Executable
exec="/cygdrive/c/Progra~1/Ethereal/tethereal"

# Stop writing to a capture file after value seconds have elapsed.
duration=60

# Capture file
capture_file=capture.cap

# Display packet summary while dumping packets
display_packets=-S
${exec} -a duration:${duration} ${display_packets} -w ${capture_file}

# Display statistics.
# Create Protocol Hierarchy Statistics listing both number of frames and bytes.
#${exec} -r ${capture_file} -q -z io,phs

# Create a table that lists all conversations that could be seen in the capture.
#${exec} -q -r ${capture_file} -z io,users,tcpip
