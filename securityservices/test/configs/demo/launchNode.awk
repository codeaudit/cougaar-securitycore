#
# awk program to start a society on multiple nodes
#

BEGIN { "pwd" | getline curdir }

# Search for lines that do not start with the # character
# Then execute the launchNode function for each line in the configuration file
! /^\#/  { nodeName=$1 ; confdirectory=$2 ; confFile=$3 ; script=$4 ; launchNode(nodeName, confdirectory, confFile, script) } 

# Function:
# Launch an xterm window and start the node in that terminal
func launchNode( nodeName, confdirectory, confFile, script )
{ 
	printf "%15-s", nodeName
	printf " %40-s", confdirectory
	print ": " confFile
	command="xterm -geometry 70x15 -sb -si -sl 2000 -title " nodeName "-" confFile " " \
		 "-e ssh " nodeName " " curdir "/start-node " nodeName " " confdirectory " " confFile " " script " " curdir " &"
	#print command
	system( command )
}
