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
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.service.ThreadControlService;
import org.cougaar.core.thread.RightsSelector;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.thread.RightsSelector;

import java.util.Comparator;

// this class is a proxy for the ThreadControlService
class ThreadControlServiceProxy extends SecureServiceProxy 
  implements ThreadControlService {
  private final ThreadControlService _tcs;
  private final Object _requestor;
  
  public ThreadControlServiceProxy(ThreadControlService tcs, Object requestor, ServiceBroker sb) {
    super(sb);
    _tcs = tcs;
    _requestor = requestor;
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
    Comparator _comparator;
    ExecutionContext _ec;
    
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
