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
import org.cougaar.core.node.service.RealTimeService;
import org.cougaar.core.agent.service.alarm.Alarm;

import org.cougaar.core.security.auth.ExecutionContext;

import java.util.Hashtable;

// this class is a proxy for the real time service 
class RealTimeServiceProxy extends SecureServiceProxy 
  implements RealTimeService {
  private final RealTimeService _rts;
  private final Object _requestor;
  private static Hashtable _alarms = new Hashtable();
  
  public RealTimeServiceProxy(RealTimeService rts, Object requestor, ServiceBroker sb) {
    super(sb);
    _rts = rts;
    _requestor = requestor;
  }
  
  public void addAlarm(Alarm alarm) {
    _rts.addAlarm(_addAlarm(alarm));
  }
  
  public void cancelAlarm(Alarm alarm) {
    _rts.cancelAlarm(_removeAlarm(alarm));
  }
  
  public long currentTimeMillis() {
    return _rts.currentTimeMillis(); 
  }
  
  private Alarm _addAlarm(Alarm alarm) {
    Alarm sa = new SecureAlarm(alarm, _scs.getExecutionContext());
    _alarms.put(alarm, sa);
    return sa;
  }
  private Alarm _removeAlarm(Alarm alarm) {
    Alarm a = (Alarm)_alarms.remove(alarm);
    return ((a != null) ? a : alarm);
  }
  
  class SecureAlarm implements Alarm {
    Alarm _alarm;
    ExecutionContext _ec;
    SecureAlarm(Alarm alarm, ExecutionContext ec) {
      _alarm = alarm; 
      _ec = ec;
    }
    public boolean cancel() {
      _scs.setExecutionContext(_ec);
      boolean retval = _alarm.cancel(); 
      _scs.resetExecutionContext();
      return retval;  
    }
    public void expire() {
      _scs.setExecutionContext(_ec);
      _alarm.expire();
      _scs.resetExecutionContext();
    }
    public long getExpirationTime() {
      _scs.setExecutionContext(_ec);
      long retval = _alarm.getExpirationTime();
      _scs.resetExecutionContext();
      return retval;
    }
    public boolean hasExpired() {
      _scs.setExecutionContext(_ec);
      boolean retval = _alarm.hasExpired();
       _scs.resetExecutionContext();
      return retval;
    }
  }// end class SecureAlarm
}