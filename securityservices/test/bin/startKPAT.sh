#! /bin/sh
# "<copyright>"
# " Copyright 2001 BBNT Solutions, LLC"
# " under sponsorship of the Defense Advanced Research Projects Agency (DARPA)."
# ""
# " This program is free software; you can redistribute it and/or modify"
# " it under the terms of the Cougaar Open Source License as published by"
# " DARPA on the Cougaar Open Source Website (www.cougaar.org)."
# ""
# " THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS"
# " PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR"
# " IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF"
# " MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT"
# " ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT"
# " HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL"
# " DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,"
# " TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR"
# " PERFORMANCE OF THE COUGAAR SOFTWARE."
# "</copyright>"


if [ "$COUGAAR_INSTALL_PATH" = "" ]; then
  echo Please set COUGAAR_INSTALL_PATH;
  exit;
fi

host=$1
port=$2

agentName=$3
if [ "$3" == "" ]; then
  agentName="PolicyDomainManager1ServletAgent";
fi

for i in ${COUGAAR_INSTALL_PATH}/lib/*.jar
do
  CP=$CP:$i
done
for i in ${COUGAAR_INSTALL_PATH}/sys/*.jar
do
  CP=$CP:$i
done

#MYPROPERTIES="-Dlog4j.rootCategory=FATAL,Junk -Dlog4j.appender.Junk=org.apache.log4j.FileAppender -Dlog4j.appender.Junk.File=/tmp/KPAT.log"

#
# The above attempt did not work.  The disadvantage of the approach below is 
# that it leaves those stupid node.log files distributed all around your 
# directories...
#
MYPROPERTIES="-Dlog4j.configuration=${COUGAAR_INSTALL_PATH}/configs/common/loggingConfig.conf"
MYPROPERTIES="${MYPROPERTIES} -Dorg.cougaar.system.path=$COUGAAR_INSTALL_PATH/sys -Dorg.cougaar.install.path=$COUGAAR_INSTALL_PATH -Dorg.cougaar.core.servlet.enable=true -Dorg.cougaar.lib.web.scanRange=100 -Dorg.cougaar.lib.web.http.port=$port -Dorg.cougaar.lib.web.https.port=-1 -Dorg.cougaar.lib.web.https.clientAuth=true"

MYMEMORY=""
MYCLASSES="kaos.kpat.applet.KPATAppletMain"
MYARGUMENTS="http://$host:$port/\$$agentName/policyAdmin true"

#echo java -classpath $CP $MYPROPERTIES $MYMEMORY $MYCLASSES $MYARGUMENTS
      java -classpath $CP $MYPROPERTIES $MYMEMORY $MYCLASSES $MYARGUMENTS

