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


import java.util.LinkedList;
import java.util.NoSuchElementException;

import org.cougaar.core.agent.Agent;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.EventService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;


public class EventAgentProxy implements EventService {
  
  private Object object;
  private ServiceBroker serviceBroker;
  private LoggingService log;
  private EventService myEventService;
  private MessageAddress myID = null;
  private LinkedList myqueue=null; 
  protected long    _pollInterval    = 80L;

  private final int THRESHOLD_SIZE_RAISE_WARNING = 1000;
 
  private Schedulable eventPublisherThread=null;
  private ThreadService threadService= null;;
  public EventAgentProxy (EventService myes,
                          Object myobj,
                          ServiceBroker sb) {
    this.myEventService=myes;
    this.object=myobj;
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    if (object instanceof Agent) {
      myID = ((Agent)object).getAgentIdentifier();
    }
    else {
      if(log.isDebugEnabled()) {
        if(object!=null) {
          log.debug(" client is :"+object.getClass().getName() );
        }
      }
    }
      
    myqueue=new LinkedList(); 
    threadService  = (ThreadService)serviceBroker.
      getService(this, ThreadService.class, null);
    if(threadService!=null) {
      eventPublisherThread=threadService.getThread(this, new CougaarEventPublisher());
      eventPublisherThread.schedule(0, _pollInterval );
      if(log.isDebugEnabled()) {
        log.debug("Event service  agent proxy for " + myID + " initialized");
      }
    }
    else {
      ServiceAvailableListener listener = new ListenForThreadServices();
      serviceBroker.addServiceListener(listener);
    }
   
    
  }

  public boolean isEventEnabled() {
    return myEventService.isEventEnabled(); 
  }
  public void event(String s) {
     if(log.isDebugEnabled()) {
        log.debug("Event  agent proxy for " + myID + "called ");
      }
    CougaarEvent cougaarEvent=new CougaarEvent(s);
    synchronized(myqueue) {
      myqueue.addLast(cougaarEvent);
    }
      
  }
  public void event(String s, Throwable t) {
     if(log.isDebugEnabled()) {
        log.debug("Event  agent proxy for " + myID + "called ");
      }
    CougaarEvent cougaarEvent=new CougaarEvent(s,t);
    synchronized(myqueue) {
      myqueue.addLast(cougaarEvent);
    }

  }

  /*
  private void startCougaarEventPublisher(ThreadService ts) {
    if(ts!=null) {
      threadService=ts;
      eventPublisherThread=ts.getThread(this, new CougaarEventPublisher());
      eventPublisherThread.schedule(0, _pollInterval );
      if(log.isDebugEnabled()) {
        log.debug(" Starting Cougaar Event publisher Thread in EventAgentproxy:");
      }
    }
  }
  */
  
  private class CougaarEventPublisher implements Runnable {
     
    public void run() {
      CougaarEvent event=null;
      if(myqueue.size()>0) {
         if(log.isDebugEnabled()) {
           log.debug(" Starting  CougaarEvent publishing  in EventAgentproxy");
         }
         if(log.isWarnEnabled()) {
           if(myqueue.size() > THRESHOLD_SIZE_RAISE_WARNING) {
             log.warn("EventService binder queue size getting too big:" + myqueue.size());
           }
         }
         //myEventService.event("CougaarEventPublisherThread --  QUEUE SIZE "+ myqueue.size());
        synchronized(myqueue) {
          try {
            event=(CougaarEvent)myqueue.removeFirst();
          }
          catch(NoSuchElementException noSuchExp) {
            if(log.isWarnEnabled()) {
              log.warn(" CougaarEvent queue is not empty but still getting NoSuchElementException --"+noSuchExp.getMessage() );
            }
          }
        }
        if(event.getThrowable()!=null) {
          if(log.isDebugEnabled()) {
            log.debug(" Cougaar Event to be published:");
          }
          myEventService.event(event.getEvent(),event.getThrowable());
        }
        else {
          if(log.isDebugEnabled()) {
            log.debug(" Cougaar Event to be published:");
          }
          myEventService.event(event.getEvent());
        }
      }
      else {
        return;
      }
    }
 
  }
  private class ListenForThreadServices  implements ServiceAvailableListener {
    
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      ServiceBroker sb = serviceBroker;
     /* if(log.isInfoEnabled()) {
        log.info(" serviceAvailable Listener called in EventAgent Proxy :");
      }
      */
      if ( (sc == ThreadService.class) &&(threadService==null) ) {
        if(log.isInfoEnabled()) {
          log.info(" Thread  Service is available now in  EventAgent Proxy ");
        }
        threadService = (ThreadService)
          sb.getService(this, ThreadService.class, null);
        
      }
    }
  }

  
 


}
