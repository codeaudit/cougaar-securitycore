/*
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
 */

package org.cougaar.core.security.access;


import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.EventService;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.agent.Agent;

import java.util.LinkedList;
import java.util.NoSuchElementException;


public class EventAgentProxy implements EventService {
  
  private Object object;
  private ServiceBroker serviceBroker;
  private LoggingService log;
  private EventService myEventService;
  private MessageAddress myID = null;
  private LinkedList myqueue=null; 
  protected long    _pollInterval    = 6L;
 
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

  private class CougaarEventPublisher implements Runnable {
     
    public void run() {
      CougaarEvent event=null;
      if(myqueue.size()>0) {
         if(log.isDebugEnabled()) {
           log.debug(" Starting  CougaarEvent publishing  in EventAgentproxy");
         }
         myEventService.event("CougaarEventPublisherThread --  QUEUE SIZE "+ myqueue.size());
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
