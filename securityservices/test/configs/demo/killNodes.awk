#
# awk program to kill a society on multiple nodes
#


BEGIN { "pwd" | getline curdir }

# Search for lines that do not start with the # character
# Then execute the launchNode function for each line in the configuration file
! /^\#/  { nodeName=$1 ; killNode(nodeName) } 

# Function:
# Kill all java programs in a given node
func killNode( nodeName )
{ 
	printf "%15-s", nodeName
	command= "ssh " nodeName " /usr/bin/killall -w -KILL java" 
	print command
	system( command )
}
