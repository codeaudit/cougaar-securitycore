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

import java.util.Comparator;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.service.ThreadControlService;
import org.cougaar.core.thread.RightsSelector;
import org.cougaar.util.UnaryPredicate;

// this class is a proxy for the ThreadControlService
class ThreadControlServiceProxy extends SecureServiceProxy 
  implements ThreadControlService {
  private final ThreadControlService _tcs;
  //private final Object _requestor;
  
  public ThreadControlServiceProxy(ThreadControlService tcs, Object requestor, ServiceBroker sb) {
    super(sb);
    _tcs = tcs;
    //_requestor = requestor;
  }

  public void setMaxRunningThreadCount(int count, int lane) {
    _tcs.setMaxRunningThreadCount(count, lane);
  }
  public void setQueueComparator(Comparator comparator, int lane) {
    _tcs.setQueueComparator(comparator, lane);
  }
  public void setRightsSelector(RightsSelector selector, int lane) {
    _tcs.setRightsSelector(selector, lane);
  }
  public boolean setQualifier(UnaryPredicate predicate, int lane) {
    return _tcs.setQualifier(predicate, lane);
  }
  public boolean setChildQualifier(UnaryPredicate predicate, int lane) {
    return _tcs.setChildQualifier(predicate, lane);
  }

    // Status
  public int runningThreadCount(int lane) {
    return _tcs.runningThreadCount(lane);
  }
  public int pendingThreadCount(int lane) {
    return _tcs.pendingThreadCount(lane);
  }
  public int activeThreadCount(int lane) {
    return _tcs.activeThreadCount(lane);
  }
  public int maxRunningThreadCount(int lane) {
    return _tcs.maxRunningThreadCount(lane);
  }

    // Default lane
  public int getDefaultLane() {
    return _tcs.getDefaultLane();
  }
  public void setDefaultLane(int lane) {
    _tcs.setDefaultLane(lane);
  }

  public int activeThreadCount() {
    return _tcs.activeThreadCount();
  }
            
  public int maxRunningThreadCount() {
    return _tcs.maxRunningThreadCount();
  }
            
  public int pendingThreadCount() {
    return _tcs.pendingThreadCount();
  }
            
  public int runningThreadCount() {
    return _tcs.runningThreadCount();
  }
            
  public void setMaxRunningThreadCount(int count) {
    _tcs.setMaxRunningThreadCount(count);
  }

  public boolean setChildQualifier(UnaryPredicate predicate) {
    UnaryPredicate sup = createSecurePredicate(predicate, _scs.getExecutionContext());
    return _tcs.setChildQualifier(sup);
  }
             
  public boolean setQualifier(UnaryPredicate predicate) {
    UnaryPredicate sup = createSecurePredicate(predicate, _scs.getExecutionContext());
    return _tcs.setQualifier(sup);
  }
            
  public void setQueueComparator(Comparator comparator) {
    Comparator sc = new SecureComparator(comparator, _scs.getExecutionContext());
    _tcs.setQueueComparator(sc);
  }
            
  public void setRightsSelector(RightsSelector selector) {
    //RightsSelector srs = new SecureRightsSelector(selector, _scs.getExecutionContext());
    _tcs.setRightsSelector(selector);
  }
 

  class SecureComparator implements Comparator {
    private Comparator _comparator;
    private ExecutionContext _ec;
    
    SecureComparator(Comparator comparator, ExecutionContext ec) {
      _comparator = comparator;
      _ec = ec;
    }
    public int compare(Object o1, Object o2) {
      int retval = 0;
      _scs.setExecutionContext(_ec);
      retval = _comparator.compare(o1, o2);
      _scs.resetExecutionContext();
      return retval;
    }      
    public boolean equals(Object obj) {
      boolean retval = false;
      _scs.setExecutionContext(_ec);
      retval = _comparator.equals(obj);
      _scs.resetExecutionContext();
      return retval;
    } 
  } // end class SecureComparator

  /*
  // NOTE: SchedulableObject has package level access 
  class SecureRightsSelector implements RightsSelector {
    RightsSelector _rs;
    ExecutionContext _ec;
    SecureRightsSelector(RightsSelector rs, ExecutionContext ec) {
      _rs = rs;
      _ec = ec; 
    }
    public SchedulableObject getNextPending() {
      SchedulableObject retval = null;
      _scs.setExecutionContext(_ec);
      retval = _rs.getNextPending();
      _scs.resetExecutionContext();
      return retval;
    }
            
    public void setScheduler(PropagatingScheduler scheduler) {
      _scs.setExecutionContext(_ec);
      _rs.setScheduler(scheduler);
      _scs.resetExecutionContext();
    }
  } // end class SecureRightsSelector
  */
} // end class ThreadControlServiceProxy
