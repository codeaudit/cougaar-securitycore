#
# awk program to kill a society on multiple nodes
#


# Search for lines that do not start with the # character
# Then execute the launchNode function for each line in the configuration file
! /^\#/  { nodeName=$1 ; killNode(nodeName) } 

# Function:
# Kill all java programs in a given node
func killNode( nodeName )
{ 
	printf "%15-s", nodeName
	command="~/demo/remote-kill " nodeName 
	print command
	system( command )
}
