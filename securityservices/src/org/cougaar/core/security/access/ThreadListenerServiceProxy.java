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

import java.util.Hashtable;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.service.ThreadListenerService;
import org.cougaar.core.thread.Schedulable;
import org.cougaar.core.thread.ThreadListener;

// this class is a proxy for the ThreadListenerService
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
  public void addListener(ThreadListener listener, int lane) {
    _tls.addListener(addThreadListener(listener), lane);
  }
            
  public void removeListener(ThreadListener listener) {
    _tls.removeListener(removeThreadListener(listener));
  }
  public void removeListener(ThreadListener listener, int lane) {
    _tls.removeListener(removeThreadListener(listener), lane);
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
