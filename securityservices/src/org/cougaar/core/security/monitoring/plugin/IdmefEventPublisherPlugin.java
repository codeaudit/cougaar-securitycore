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

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.AgentRegistration;
import org.cougaar.core.security.monitoring.idmef.Registration;
import org.cougaar.core.service.EventService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Iterator;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.XMLSerializable;

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
      if (o instanceof Event) {
        IDMEF_Message msg = ((Event) o).getEvent();
        if (msg instanceof Registration ||
            msg instanceof AgentRegistration) {
          return false;
        }
        return (msg instanceof Alert);
      }
      /*
      if (o instanceof Event ) {
	Event e=(Event)o;
	IDMEF_Message msg=e.getEvent();
	if(msg instanceof Registration){
	  return false;
	}
	else if(msg instanceof AgentRegistration) {
	  return false;
	}
        Alert a = (Alert)msg; 
        Classification []cls = a.getClassifications();
        for(int i = 0; i < cls.length; i++) {
          if(cls[i].getName().equals(IdmefClassifications.LOGIN_FAILURE)) {
            return true;
          }
        }
      }
      */
      return false;
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
    if (_eventService.isEventEnabled()) {
      while(eventiterator.hasNext()) {
	Event foo=(Event)eventiterator.next();
        Alert event = (Alert) foo.getEvent();
// 	Alert event=(Alert)eventiterator.next();
        StringBuffer s = new StringBuffer("[STATUS] IDMEF(");
        s.append(agentId.toAddress()).append(')');

        Classification cs[] = event.getClassifications();
        if (cs != null && cs.length != 0) {
          s.append(" Classification(");
          for (int i = 0; i < cs.length; i++) {
            if (i != 0) {
              s.append(',');
            }
            s.append(cs[i].getName());
          }
          s.append(')');
        }
        Source [] srcs = event.getSources();
        if (srcs != null && srcs.length != 0) {
          s.append(" Source(");
          for (int i = 0; i < srcs.length; i++) {
            if (i != 0) {
              s.append(',');
            }
            s.append(srcs[i].getIdent());
            IDMEF_Node node = srcs[i].getNode();
            if (node != null) {
              Address [] addrs = node.getAddresses();
              if (addrs.length != 0) {
                s.append(':');
                s.append(addrs[0].getAddress());
              }
            }
          }
          s.append(')');
        }

        Target [] tgts = event.getTargets();
        if (tgts != null && tgts.length != 0) {
          s.append(" Target(");
          for (int i = 0; i < tgts.length; i++) {
            if (i != 0) {
              s.append(',');
            }
            s.append(tgts[i].getIdent());
            IDMEF_Node node = tgts[i].getNode(); 
            if (node != null) {
              Address [] addrs = node.getAddresses();
              if (addrs.length != 0) {
                s.append(':');
                for (int j = 0; j < addrs.length; j++) {
                  if (j != 0) {
                    s.append('|');
                  }
                  s.append(addrs[j].getCategory()).append('=');
                  s.append(addrs[j].getAddress());
                }
              }
            }
          }
          s.append(')');
        }
        
        AdditionalData [] data = event.getAdditionalData();
        if (data != null && data.length != 0) {
          s.append(" AdditionalData(");
          for (int i = 0; i < data.length; i++) {
            if (i != 0) {
              s.append(',');
            }
            s.append(data[i].getMeaning());
            s.append(':');
            if (data[i].getAdditionalData() != null) {
              s.append(data[i].getAdditionalData());
            } else {
              XMLSerializable xml = data[i].getXMLData();
              if (xml instanceof Agent) {
                Agent agent = (Agent) xml;
                s.append(agent.getName());
              }
            }
          }
        }
        s.append(')');
        _eventService.event(s.toString());
      }
    }
  }

}
