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

LIBPATHS=$COUGAAR_INSTALL_PATH/lib/bootstrap.jar

# pass in "NodeName" to run a specific named Node

MYPROPERTIES="-Dorg.cougaar.bootstrap.Bootstrapper.loud=shout -Dorg.cougaar.system.path=$COUGAAR_INSTALL_PATH/sys -Dorg.cougaar.install.path=$COUGAAR_INSTALL_PATH -Dorg.cougaar.core.servlet.enable=true -Dorg.cougaar.lib.web.scanRange=100 -Dorg.cougaar.lib.web.http.port=8893 -Dorg.cougaar.lib.web.https.port=-1 -Dorg.cougaar.lib.web.https.clientAuth=true -Xbootclasspath/p:$COUGAAR_INSTALL_PATH/lib/javaiopatch.jar"

MYMEMORY=""
MYCLASSES="org.cougaar.bootstrap.Bootstrapper kaos.kpat.applet.KPATAppletMain"
MYARGUMENTS="http://localhost:8893/\$EnclaveOnePolicyManagerServlet/policyAdmin true"

echo java $MYPROPERTIES $MYMEMORY -classpath $LIBPATHS $MYCLASSES $MYARGUMENTS $2 $3
java $MYPROPERTIES $MYMEMORY -classpath $LIBPATHS $MYCLASSES $MYARGUMENTS $2 $3

