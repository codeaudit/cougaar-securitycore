/**
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 *
 */

package org.cougaar.core.security.access;

import java.security.PrivilegedAction;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.SchedulerService;
import org.cougaar.util.Trigger;

import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.JaasClient;

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