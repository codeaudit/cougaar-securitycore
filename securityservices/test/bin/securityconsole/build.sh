#!/bin/csh -f

# <copyright>
#  Copyright 1997-2001 ISSRL The University of Memphis,
#  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the Cougaar Open Source License as published by
#  DARPA on the Cougaar Open Source Website (www.cougaar.org).
#
#  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
#  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
#  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
#  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
#  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
#  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
#  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#  PERFORMANCE OF THE COUGAAR SOFTWARE.
# </copyright>

# Security Console needs SecurityServices provided by NAI
# set the right path to the following variable



set LIBPATHS="$COUGAAR_INSTALL_PATH/lib/core.jar:$COUGAAR_INSTALL_PATH/lib/util.jar:$COUGAAR_INSTALL_PATH/lib/planserver.jar:$COUGAAR_INSTALL_PATH/lib/glm.jar:$COUGAAR_INSTALL_PATH/sys/jcchart.jar:$COUGAAR_INSTALL_PATH/sys/xerces.jar:$COUGAAR_INSTALL_PATH/sys/servlet.jar:$COUGAAR_INSTALL_PATH/lib/idmef.jar:$COUGAAR_INSTALL_PATH/lib/securityservices.jar:$COUGAAR_INSTALL_PATH/sys/jpython.jar:$COUGAAR_INSTALL_PATH/lib/aggagent.jar:$COUGAAR_INSTALL_PATH/sys/junit.jar:$COUGAAR_INSTALL_PATH/sys/log4j.jar:$COUGAAR_INSTALL_PATH/sys/log4j.jar"

set SOURCE="/home/u/rtripath/UL/secconsole/seccon/src/edu/memphis/issrl/snapingui/*.java"
set SOURCE="$SOURCE /home/u/rtripath/UL/secconsole/seccon/src/edu/memphis/issrl/communication/*.java"
set SOURCE="$SOURCE /home/u/rtripath/UL/secconsole/seccon/src/edu/memphis/issrl/querymanager/*.java"
set SOURCE="$SOURCE /home/u/rtripath/UL/secconsole/seccon/src/edu/memphis/issrl/seccon/*.java"
set SOURCE="$SOURCE /home/u/rtripath/UL/secconsole/seccon/src/edu/memphis/issrl/seccon/qbe/*.java"
set SOURCE="$SOURCE /home/u/rtripath/UL/secconsole/seccon/src/edu/memphis/issrl/seccon/communication/*.java"
set SOURCE="$SOURCE /home/u/rtripath/UL/secconsole/seccon/src/edu/memphis/issrl/seccon/querymanager/*.java"
set SOURCE="$SOURCE /home/u/rtripath/UL/secconsole/seccon/src/edu/memphis/issrl/mrmanager/*.java"
set SOURCE="$SOURCE /home/u/rtripath/UL/secconsole/seccon/src/edu/memphis/issrl/test/*.java"
set SOURCE="$SOURCE /home/u/rtripath/UL/secconsole/seccon/src/test/*.java"

set OUTDIR="."

set JAVACARGS="-deprecation"

javac $JAVACARGS -classpath $LIBPATHS -d $OUTDIR $SOURCE

jar cf umemphis.jar edu
jarsigner -keystore ${COUGAAR_SECURITY_SERVICES}/test/configs/sign-jars/signingCA_keystore -storepass keystore umemphis.jar privileged
cp /home/u/rtripath/UL/secconsole/seccon/classes/umemphis.jar $CIP/lib/

