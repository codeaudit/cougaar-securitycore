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

set PCKGS="edu.memphis.issrl.mrmanager"
set PCKGS="$PCKGS edu.memphis.issrl.snapingui"
set PCKGS="$PCKGS edu.memphis.issrl.seccon.communication"
set PCKGS="$PCKGS edu.memphis.issrl.seccon.querymanager"
set PCKGS="$PCKGS edu.memphis.issrl.seccon.qbe"
#set PCKGS="$PCKGS edu.memphis.issrl.seccon"

set SRCPATH="../../src"

set JDOCPARAMS="-public"

set OUTDIR="../../doc/api"


javadoc $JDOCPARAMS  -d $OUTDIR -sourcepath $SRCPATH $PCKGS
