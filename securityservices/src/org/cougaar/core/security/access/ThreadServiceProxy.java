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

import java.util.TimerTask;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;

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
    Runnable sr = new SecureRunnable(runnable, _scs.getExecutionContext());
    return new SecureSchedulable(_ts.getThread(consumer, sr), 
                                 _scs.getExecutionContext());
  }
            
  public Schedulable getThread(Object consumer, Runnable runnable, String name) {
    Runnable sr = new SecureRunnable(runnable, _scs.getExecutionContext());
    return new SecureSchedulable(_ts.getThread(consumer, sr, name), 
                                 _scs.getExecutionContext());
  }
  public Schedulable getThread(Object consumer, Runnable runnable, String name,
			       int lane) {
    Runnable sr = new SecureRunnable(runnable, _scs.getExecutionContext());
    return new SecureSchedulable(_ts.getThread(consumer, sr, name, lane), 
                                 _scs.getExecutionContext());
  }

  // B11_0 ThreadService interface, but isn't part of the HEAD.  We SHOULD NOT use these
  // methods.  Instead, we should invoke getThread() and invoke Schedulable.schedule().
  public void schedule(TimerTask task, long delay) {
    throw new SecurityException("schedule(TimerTask, long) has been deprecated.");
  }

  public void schedule(TimerTask task, long delay, long interval) {
    throw new SecurityException("schedule(TimerTask, long, long) has been deprecated.");
  }
            
  public void scheduleAtFixedRate(TimerTask task, long delay, long interval) {
    throw new SecurityException("scheduleAtFixedRate(TimerTask, long, long) has been deprecated.");
  }
  
  class SecureSchedulable implements Schedulable {
    Schedulable _schedulable;
    ExecutionContext _ec;
    SecureSchedulable(Schedulable scheduable, ExecutionContext ec) {
      _schedulable = scheduable;
      _ec = ec;
    }

    /**
     * Lane
     */
    public int getLane() {
      int retval = 0;
      _scs.setExecutionContext(_ec);
      retval = _schedulable.getLane();
      _scs.resetExecutionContext();
      return retval;
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
    public void cancelTimer() {
      _scs.setExecutionContext(_ec);
      _schedulable.cancelTimer();
      _scs.resetExecutionContext();
    }
    public void schedule(long delay) {
      _scs.setExecutionContext(_ec);
      _schedulable.schedule(delay);
      _scs.resetExecutionContext();
    }
    public void schedule(long delay, long interval) {
      _scs.setExecutionContext(_ec);
      _schedulable.schedule(delay, interval);
      _scs.resetExecutionContext();
    }
    public void scheduleAtFixedRate(long delay, long interval) {
      _scs.setExecutionContext(_ec);
      _schedulable.scheduleAtFixedRate(delay, interval);
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
  
  class SecureRunnable implements Runnable {
    Runnable _r;
    ExecutionContext _ec;
    SecureRunnable(Runnable r, ExecutionContext ec) {
      _r = r;
      _ec = ec;
    } 
    public void run() {
      _scs.setExecutionContext(_ec);
      _r.run();
      _scs.resetExecutionContext();
    }
  }// end class SecureRunnable
}
