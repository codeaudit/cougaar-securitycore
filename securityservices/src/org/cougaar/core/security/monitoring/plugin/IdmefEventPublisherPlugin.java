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


package org.cougaar.core.security.monitoring.plugin;

import java.util.Collection;
import java.util.Iterator;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.EventService;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.blackboard.IncrementalSubscription;

// Cougaar Security Services
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.idmef.Registration;
import org.cougaar.core.security.monitoring.idmef.AgentRegistration;

import edu.jhuapl.idmef.IDMEF_Message;

public class IdmefEventPublisherPlugin
  extends ComponentPlugin
{
  private IncrementalSubscription _idmefevents;
  private LoggingService _log;
  private EventService _eventService;

  /**
   * A predicate that matches all "Event object which is not registration "
   */
  class IdemfEventPredicate implements UnaryPredicate{
    public boolean execute(Object o) {
      boolean ret = false;
      if (o instanceof Event ) {
	Event e=(Event)o;
	IDMEF_Message msg=e.getEvent();
	if(msg instanceof Registration){
	  return false;
	}
	else if(msg instanceof AgentRegistration) {
	  return false;
	}
	ret=true;      
      }
      return ret;
    }
  }

 
  protected void setupSubscriptions() {
    _log = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
    _eventService = (EventService)getBindingSite().getServiceBroker().getService
      (this, EventService.class, null);
    if (_log.isDebugEnabled()) {
      _log.debug("IdmefEventPublisherPlugin setupSubscription()");
    }
    _idmefevents = (IncrementalSubscription)
      getBlackboardService().subscribe(new IdemfEventPredicate());
  }
  
  protected void execute () {
    Collection eventcollection = _idmefevents.getAddedCollection();
    Iterator eventiterator = eventcollection.iterator();
    Object event = null;
    if (_eventService.isEventEnabled()) {
      while(eventiterator.hasNext()) {
	event=(Object)eventiterator.next();
	String s = "[IDMEF] " + event.toString();
	_eventService.event(s);
      }
    }
  }

}
