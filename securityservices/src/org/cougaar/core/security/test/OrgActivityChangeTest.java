/*
 * <copyright>
 *  Copyright 1997-2001 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */
package org.cougaar.core.security.test;

import java.io.*;
import java.lang.*;
import java.util.*;
import java.security.*;
import javax.security.auth.*;

import org.cougaar.core.blackboard.*;
import org.cougaar.core.component.*;
import org.cougaar.core.plugin.*;
import org.cougaar.core.service.*;
import org.cougaar.util.*;

import org.cougaar.core.security.services.auth.*;
import org.cougaar.core.security.auth.*;

import org.cougaar.glm.ldm.oplan.*;

public class OrgActivityChangeTest extends ComponentPlugin
{
    IncrementalSubscription _sub;
    OrgActivity _orgActivity;
    
    private UnaryPredicate ORGACTIVITY_PRED = 
       new UnaryPredicate() {
          public boolean execute(Object o) {
             return (o instanceof OrgActivity);
          }
       };
    
    private BlackboardService _bbs = null;
    private LoggingService _log = null;
  
    public void setParameter(Object params) {
       List l = (List)params;
       Iterator i = l.iterator();
       for(int x = 0; i.hasNext(); x++) {
         System.out.println("item(" + x + ") = " + i.next());
       }
    }

    protected void setupSubscriptions() {
      ServiceBroker sb = getServiceBroker();
      _log = (LoggingService)sb.getService(this, LoggingService.class, null);
      _bbs = getBlackboardService();
      _log.debug("subscribing to OrgActivity");
      _sub = (IncrementalSubscription)_bbs.subscribe(ORGACTIVITY_PRED);
    }

    public void execute() {
      if(_sub.hasChanged()) {
        Collection c = _sub.getAddedCollection();
        if(!c.isEmpty()) {
          OrgActivity oa = (OrgActivity)c.iterator().next();
          printOrgActivity(oa);
          _log.debug("changing OrgActivity");
          oa.setActivityName("CHANGED-test-name");
          oa.setActivityType("CHANGED-test-type");
          oa.setOrgID("CHANGED-test-id");
          _log.debug("publish change OrgActivity");
          _bbs.publishChange(oa);
          printOrgActivity(oa);
        }
      }
    }
    
    private void printOrgActivity(OrgActivity oa) {
      _log.debug("OrgActivity object: " + oa);
      _log.debug("OrgActivity name: " + oa.getActivityName());
      _log.debug("OrgActivity type: " + oa.getActivityType());
      _log.debug("OrgActivity id: " + oa.getOrgID());
    }
}
