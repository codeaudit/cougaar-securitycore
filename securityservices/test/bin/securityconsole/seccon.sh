#!/bin/bash -f

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

node="umseccon"


PROPFILE="$COUGAAR_INSTALL_PATH/configs/security/data/MainApplication.properties"
# Search and replace properties to customize for current environment
${COUGAAR_SECURITY_SERVICES}/test/bin/sarep -v '\.\./\.\./' ${COUGAAR_INSTALL_PATH}/configs/security/  ${PROPFILE}

MYDOMAINS=""
MYMEMORY="-Xms384m -Xmx448m"

MYCONFIGPATH="-Dorg.cougaar.config.path=$COUGAAR_INSTALL_PATH/csmart/data/common/\;$COUGAAR_INSTALL_PATH/configs/\;"

MYCLASSPATH="${COUGAAR_INSTALL_PATH}/lib/bootstrap.jar"

MYPROPERTIES="$MYDOMAINS  -Dorg.cougaar.install.path=$COUGAAR_INSTALL_PATH -Duser.timezone=GMT -Dorg.cougaar.core.cluster.startTime=08/10/2005 -Dorg.cougaar.domain.planning.ldm.lps.ComplainingLP.level=0 -Dorg.cougaar.core.cluster.SharedPlugInManager.watching=false"
MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.security.crypto.config=cryptoPolicy.xml"
MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.security.role=$USER"
MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.workspace=$COUGAAR_INSTALL_PATH/workspace"
MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.node.name=$node"
MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.core.security.standalone=true"
MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.core.logging.config.filename=loggingConfig.conf"
MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.core.logging.log4j.appender.SECURITY.File=kpat.log"
MYPROPERTIES="$MYPROPERTIES -Dlog4j.configuration=$COUGAAR_INSTALL_PATH/configs/security/data/MainApp-log4j.properties"

JAVAARGS="$MYPROPERTIES $MYMEMORY $MYCONFIGPATH -cp $MYCLASSPATH"

#echo exec java $JAVAARGS org.cougaar.bootstrap.Bootstrapper edu.memphis.issrl.snapingui.MainApplication $PROPFILE
exec java $JAVAARGS org.cougaar.bootstrap.Bootstrapper edu.memphis.issrl.snapingui.MainApplication $PROPFILE
