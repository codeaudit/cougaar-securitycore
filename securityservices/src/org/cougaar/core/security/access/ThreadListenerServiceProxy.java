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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.ThreadListenerService;
import org.cougaar.core.thread.Schedulable;
import org.cougaar.core.thread.ThreadListener;

import org.cougaar.core.security.auth.ExecutionContext;

import java.util.Hashtable;
import java.util.TimerTask;

// this class is a proxy for the alarm service 
class ThreadListenerServiceProxy extends SecureServiceProxy 
  implements ThreadListenerService {
  private final ThreadListenerService _tls;
  private final Object _requestor;
  private static Hashtable _listeners = new Hashtable();
  
  public ThreadListenerServiceProxy(ThreadListenerService tls, Object requestor, ServiceBroker sb) {
    super(sb);
    _tls = tls;
    _requestor = requestor;
  }
  
  public void addListener(ThreadListener listener) {
    _tls.addListener(addThreadListener(listener));
  }
            
  public void removeListener(ThreadListener listener) {
    _tls.removeListener(removeThreadListener(listener));
  }

  private ThreadListener addThreadListener(ThreadListener listener) {
    ThreadListener stl = new SecureThreadListener(listener, _scs.getExecutionContext());
    _listeners.put(listener, stl);
    return stl;
  }
  private ThreadListener removeThreadListener(ThreadListener listener) {
    return (ThreadListener)_listeners.remove(listener); 
  }
  class SecureThreadListener implements ThreadListener {
    ThreadListener _threadListener;
    ExecutionContext _ec;
    
    SecureThreadListener(ThreadListener threadListener, ExecutionContext ec) {
      _threadListener = threadListener;
      _ec = ec;
    }
    public void rightGiven(String consumer) {
      _scs.setExecutionContext(_ec);
      _threadListener.rightGiven(consumer);
      _scs.resetExecutionContext();
    }       
    public void rightReturned(String consumer) {
      _scs.setExecutionContext(_ec);
      _threadListener.rightReturned(consumer);
      _scs.resetExecutionContext();
    }      
    public void threadDequeued(Schedulable schedulable, Object consumer) {
      _scs.setExecutionContext(_ec);
      _threadListener.threadDequeued(schedulable, consumer);
      _scs.resetExecutionContext();
    }
    public void threadQueued(Schedulable schedulable, Object consumer) {
      _scs.setExecutionContext(_ec);
      _threadListener.threadQueued(schedulable, consumer);
      _scs.resetExecutionContext();
    } 
    public void threadStarted(Schedulable schedulable, Object consumer) {
      _scs.setExecutionContext(_ec);
      _threadListener.threadStarted(schedulable, consumer);
      _scs.resetExecutionContext();
    }   
    public void threadStopped(Schedulable schedulable, Object consumer) {
      _scs.setExecutionContext(_ec);
      _threadListener.threadStopped(schedulable, consumer);
      _scs.resetExecutionContext();
    }
  } // end class SecureThreadListener
}