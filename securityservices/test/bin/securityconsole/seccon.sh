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

LIBPATHS="$COUGAAR_INSTALL_PATH/lib/overlay.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/core.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/util.jar"

LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/bootstrap.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/securebootstrapper.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/CougaarCRLextensions.jar"

LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/planserver.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/glm.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/aggagent.jar"

LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/idmef.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/securityservices.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/kaos.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/safe.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/jas.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/mail.jar"



LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/jcchart451K.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/xerces.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/servlet.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/jpython.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/junit.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/log4j.jar"

LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/xml4j.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/xmlparserv2.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/ibmpkcs.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/jce1_2_1.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/servlet.jar"
LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/sys/tomcat_40.jar"

LIBPATHS="$LIBPATHS:$COUGAAR_INSTALL_PATH/lib/umemphis.jar"


MYDOMAINS=""

MYPROPERTIES="$MYDOMAINS  -Dorg.cougaar.install.path=$COUGAAR_INSTALL_PATH -Duser.timezone=GMT -Dorg.cougaar.core.cluster.startTime=08/10/2005 -Dorg.cougaar.domain.planning.ldm.lps.ComplainingLP.level=0 -Dorg.cougaar.core.cluster.SharedPlugInManager.watching=false"

MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.security.crypto.config=cryptoPolicy.xml"
MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.security.role=$USER"
MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.workspace=$COUGAAR_INSTALL_PATH/workspace"
MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.node.name=$node"
MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.core.security.standalone=true"

MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.core.logging.config.filename=loggingConfig.conf"
MYPROPERTIES="$MYPROPERTIES -Dorg.cougaar.core.logging.log4j.appender.SECURITY.File=kpat.log"


PROPFILE="$COUGAAR_INSTALL_PATH/configs/security/data/MainApplication.properties"
${COUGAAR_SECURITY_SERVICES}/test/bin/sarep -v '\.\./\.\./' ${COUGAAR_INSTALL_PATH}/configs/security/  ${PROPFILE}
JAVARGS="$MYPROPERTIES  -Dlog4j.configuration=$COUGAAR_INSTALL_PATH/configs/security/data/MainApp-log4j.properties"

exec java $JAVARGS -cp $LIBPATHS edu.memphis.issrl.snapingui.MainApplication $PROPFILE
