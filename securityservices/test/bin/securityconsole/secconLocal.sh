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

LIBPATHS="$COUGAAR_INSTALL_PATH/lib/core.jar:$COUGAAR_INSTALL_PATH/lib/util.jar:$COUGAAR_INSTALL_PATH/lib/planserver.jar:$COUGAAR_INSTALL_PATH/lib/glm.jar:$COUGAAR_INSTALL_PATH/sys/jcchart451K.jar:$COUGAAR_INSTALL_PATH/sys/xerces.jar:$COUGAAR_INSTALL_PATH/sys/servlet.jar:$COUGAAR_INSTALL_PATH/lib/idmef.jar:$COUGAAR_INSTALL_PATH/lib/securityservices.jar:$COUGAAR_INSTALL_PATH/sys/jpython.jar:$COUGAAR_INSTALL_PATH/lib/aggagent.jar:$COUGAAR_INSTALL_PATH/sys/junit.jar:$COUGAAR_INSTALL_PATH/sys/log4j.jar:$COUGAAR_INSTALL_PATH/lib/bootstrap.jar:$COUGAAR_INSTALL_PATH/lib/umemphis.jar"


PROPFILE="$COUGAAR_INSTALL_PATH/configs/security/data/MainApplication.properties"
${COUGAAR_SECURITY_SERVICES}/test/bin/sarep -v '\.\./\.\./' ${COUGAAR_INSTALL_PATH}/configs/security/  ${PROPFILE}
JAVARGS="-Dlog4j.debug=false"
JAVARGS="$JAVARGS  -Dlog4j.configuration=$COUGAAR_INSTALL_PATH/configs/security/data/MainApp-log4j.properties"

exec java $JAVARGS -cp $LIBPATHS edu.memphis.issrl.snapingui.MainApplication $PROPFILE
