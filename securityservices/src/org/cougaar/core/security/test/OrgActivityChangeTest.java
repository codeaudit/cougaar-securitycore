/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 

package org.cougaar.core.security.test;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.util.UnaryPredicate;

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
