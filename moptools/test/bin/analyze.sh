#!/bin/sh

# Executable
exec="tethereal"

# Stop writing to a capture file after value seconds have elapsed.
duration=60

# Capture file
capture_file=capture.cap

# Display packet summary while dumping packets
display_packets=-S

# Display statistics.
# Create Protocol Hierarchy Statistics listing both number of frames and bytes.
${exec} -r ${capture_file} -q -z io,phs

# Create a table that lists all conversations that could be seen in the capture.
#${exec} -q -r ${capture_file} -z io,users,tcpip
