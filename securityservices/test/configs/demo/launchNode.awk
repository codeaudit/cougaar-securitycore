#
# awk program to start a society on multiple nodes
#


# Search for lines that do not start with the # character
# Then execute the launchNode function for each line in the configuration file
! /^\#/  { nodeName=$1 ; directory=$2 ; confFile=$3 ; script=$4 ; launchNode(nodeName, directory, confFile, script) } 

# Function:
# Launch an xterm window and start the node in that terminal
func launchNode( nodeName, directory, confFile, script )
{ 
	printf "%15-s", nodeName
	printf " %40-s", directory
	print ": " confFile
	command="xterm -geometry 70x15 -sb -si -sl 2000 -title " nodeName "-" confFile " " \
		 "-e ~/demo/remote-launch " nodeName " " directory " " confFile " " script " &"
	#print command
	system( command )
}
