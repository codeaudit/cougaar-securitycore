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
import org.cougaar.core.service.AlarmService;
import org.cougaar.core.agent.service.alarm.Alarm;
import org.cougaar.core.agent.service.alarm.PeriodicAlarm;

import org.cougaar.core.security.auth.ExecutionContext;

// this class is a proxy for the alarm service 
class AlarmServiceProxy extends SecureServiceProxy 
  implements AlarmService {
  private final AlarmService _as;
  private final Object _requestor;
  
  public AlarmServiceProxy(AlarmService as, Object requestor, ServiceBroker sb) {
    super(sb);
    _as = as;
    _requestor = requestor;
  }
  
  public void addAlarm(Alarm alarm) {
    _as.addAlarm(createSecureAlarm(alarm));
  }
  
  public void addRealTimeAlarm(Alarm alarm) {
    _as.addRealTimeAlarm(createSecureAlarm(alarm));
  }
  
  public long currentTimeMillis() {
    return _as.currentTimeMillis(); 
  }
 
  private Alarm createSecureAlarm(Alarm alarm) {
    Alarm sAlarm = null;
    if(alarm != null) {
      if(alarm instanceof PeriodicAlarm) {
        sAlarm = new SecurePeriodicAlarm((PeriodicAlarm)alarm, _scs.getExecutionContext());
      }
      else {
        sAlarm = new SecureAlarm(alarm, _scs.getExecutionContext());
      }
    }
    return sAlarm;
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

  class SecurePeriodicAlarm extends SecureAlarm
    implements PeriodicAlarm {
    PeriodicAlarm _pAlarm;
    SecurePeriodicAlarm(PeriodicAlarm pAlarm, ExecutionContext ec) {
      super(pAlarm, ec);
      _pAlarm = pAlarm;
    }
    public void reset(long currentTime) {
      _scs.setExecutionContext(_ec);
      _pAlarm.reset(currentTime);
      _scs.resetExecutionContext();
    }
  }// end SecurePeriodicAlarm   
}
