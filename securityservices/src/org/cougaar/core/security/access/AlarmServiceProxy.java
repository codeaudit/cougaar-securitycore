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

import org.cougaar.core.agent.service.alarm.Alarm;
import org.cougaar.core.agent.service.alarm.PeriodicAlarm;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.service.AlarmService;

// this class is a proxy for the alarm service 
class AlarmServiceProxy extends SecureServiceProxy 
  implements AlarmService {
  private transient final AlarmService _as;
  
  public AlarmServiceProxy(AlarmService as, Object requestor, ServiceBroker sb) {
    super(sb);
    _as = as;
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
    private transient Alarm _alarm;
    transient ExecutionContext _ec;
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
    private transient PeriodicAlarm _pAlarm;
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
