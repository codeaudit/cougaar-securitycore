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
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;

import org.cougaar.core.security.auth.ExecutionContext;

import java.util.TimerTask;

// this class is a proxy for the ThreadService
class ThreadServiceProxy extends SecureServiceProxy 
  implements ThreadService {
  private final ThreadService _ts;
  private final Object _requestor;
  
  public ThreadServiceProxy(ThreadService ts, Object requestor, ServiceBroker sb) {
    super(sb);
    _ts = ts;
    _requestor = requestor;
  }
  public Schedulable getThread(Object consumer, Runnable runnable) {
    return new SecureSchedulable(_ts.getThread(consumer, runnable), 
                                 _scs.getExecutionContext());
  }
            
  public Schedulable getThread(Object consumer, Runnable runnable, String name) {
    return new SecureSchedulable(_ts.getThread(consumer, runnable, name), 
                                 _scs.getExecutionContext());
  }
  
  public void schedule(TimerTask task, long delay) {
    _ts.schedule(new SecureTimerTask(task, _scs.getExecutionContext()), 
                 delay);
  }

  public void schedule(TimerTask task, long delay, long interval) {
    _ts.schedule(new SecureTimerTask(task, _scs.getExecutionContext()), 
                 delay, 
                 interval);
  }
            
  public void scheduleAtFixedRate(TimerTask task, long delay, long interval) {
    _ts.scheduleAtFixedRate(new SecureTimerTask(task, _scs.getExecutionContext()), 
                            delay, 
                            interval);
  }

  class SecureSchedulable implements Schedulable {
    Schedulable _schedulable;
    ExecutionContext _ec;
    SecureSchedulable(Schedulable scheduable, ExecutionContext ec) {
      _schedulable = scheduable;
      _ec = ec;
    }
    public boolean cancel() {
      boolean retval = false;
      _scs.setExecutionContext(_ec);
      retval = _schedulable.cancel();
      _scs.resetExecutionContext();
      return retval;
    }
    public Object getConsumer() {
      Object retval = null;
      _scs.setExecutionContext(_ec);
      retval = _schedulable.getConsumer();
      _scs.resetExecutionContext();
      return retval; 
    }
    public int getState() {
      int retval = 0;
      _scs.setExecutionContext(_ec);
      retval = _schedulable.getState();
      _scs.resetExecutionContext();
      return retval; 
    }
    public void start() {
      _scs.setExecutionContext(_ec);
      _schedulable.start();
      _scs.resetExecutionContext();
    }
  } // end class SecureSchedulable
  
  class SecureTimerTask extends TimerTask {
    TimerTask _timerTask;
    ExecutionContext _ec;
    SecureTimerTask(TimerTask timerTask, ExecutionContext ec) {
      _timerTask = timerTask; 
      _ec = ec;
    }
    public boolean cancel() {
      boolean retval = false;
      _scs.setExecutionContext(_ec);
      retval = _timerTask.cancel();
      _scs.resetExecutionContext();
      return retval;
    }
    public void run() {
      _scs.setExecutionContext(_ec);
      _timerTask.run();
      _scs.resetExecutionContext();
    }
    public long scheduledExecutionTime() {
      long retval = 0L;
      _scs.setExecutionContext(_ec);
      retval = _timerTask.scheduledExecutionTime();
      _scs.resetExecutionContext();
      return retval; 
    }
  }// end class SecureTimerTask
}