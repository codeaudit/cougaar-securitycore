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
 
 
 
 
 
 
 
 


package org.cougaar.core.security.access;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.JaasClient;
import org.cougaar.core.service.SchedulerService;
import org.cougaar.util.Trigger;

import java.util.Hashtable;

/** 
 * Proxy class to shield the real scheduler from clients.  This proxy
 * will set the execution context for a trigger (plugin's callback) during
 * the initialization of a plugin.  The execution context will be set as
 * a JAAS context during the execution of the callback.
 */
class SchedulerServiceProxy extends SecureServiceProxy
  implements SchedulerService {
  private SchedulerService _scheduler;
  private Object _requestor;
  
  // for Trigger to SecureTrigger mapping
  private static Hashtable _triggerTable = new Hashtable();
    
  SchedulerServiceProxy(SchedulerService ss, Object requestor, ServiceBroker sb) {
    super(sb);
    _scheduler = ss;
    _requestor = requestor;
  }
  public Trigger register(Trigger t) {
    return _scheduler.register(addTrigger(t));
  }
  
  public void unregister(Trigger t) {
    _scheduler.unregister(removeTrigger(t));
  }
   
  private Trigger addTrigger(Trigger t) {
    Trigger st = new SecureTrigger(t, _scs.getExecutionContext());
    _triggerTable.put(t, st);
    return st;
  }
    
  private Trigger removeTrigger(Trigger t) {
    return(Trigger)_triggerTable.remove(t); 
  }
    
  private class SecureTrigger implements Trigger {
    private Trigger _trigger;
    private ExecutionContext _ec;
    public SecureTrigger(Trigger t, ExecutionContext ec) {
      _trigger = t;
      _ec = ec;
    }
    public void trigger() {
      _scs.setExecutionContext(_ec);
      // set the jaas context here
       JaasClient jc = new JaasClient();
       jc.doAs(_ec, 
               new java.security.PrivilegedAction() {
                 public Object run() {
                   _trigger.trigger();
                   return null;
                 }
               }, false);
      _scs.resetExecutionContext();
    }
  } // end SecureTrigger
} // end SchedulerServiceProxy
