#!/bin/sh
echo "====> In attack script - Doing a bad thing now"
echo "This is a bad configuration file" > "temp-`date +%b-%d-%X`" 

# Kill existing java processes
killall -9 java

# Search startup file

# Search and replace -D properties


# Enable user authentication over HTTP (or HTTPS)
# org.cougaar.lib.web.tomcat.enableAuth=false

