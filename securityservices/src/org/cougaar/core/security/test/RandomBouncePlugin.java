/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
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
package org.cougaar.core.security.test;

import java.util.*;

// Cougaar core services
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.*;
import org.cougaar.core.util.UID;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.lib.web.service.NamingServerRegistry;
import org.cougaar.util.UnaryPredicate;

import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;

/**
 * 
 *
 */
public class RandomBouncePlugin extends ComponentPlugin {
  /**
   * for set/get DomainService
   */
  protected DomainService  _domainService;
  private LoggingService  _log;
  private UIDService _uidService;
  private ServiceBroker _sb;
  private Hashtable       _sent = new Hashtable();
  private Hashtable       _agentList = new Hashtable();
  
  private UnaryPredicate  _pred = new UnaryPredicate() {
      public boolean execute(Object obj) {
        if(obj instanceof CmrRelay) {
          CmrRelay relay = (CmrRelay)obj;
          if(relay.getContent() instanceof UID) {
            if(!relay.getSource().equals(_agentId)) {
              return true; 
            }
          }
        }
        return false;
      }
    };

  private IncrementalSubscription _subscription;
  private ClusterIdentifier _destination;
  private ClusterIdentifier _agentId;
  private CmrFactory _cmrFactory;
  private int _sendCount = -1;
  
  public void initialize() {
    super.initialize();
    ServiceBroker sb = getServiceBroker();
    _log = (LoggingService) sb.getService(this, LoggingService.class, null);
    _uidService = (UIDService) sb.getService(this, UIDService.class, null);
    _sb = sb;
  }

  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService aDomainService) {
    _domainService = aDomainService;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return _domainService;
  }

  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;
    _sendCount = Integer.parseInt(l.remove(0).toString());
  }

  protected void execute() {
    if (_subscription.hasChanged()) {
      Enumeration added = _subscription.getAddedList();
      BlackboardService bbs = getBlackboardService();
      while (added.hasMoreElements()) {
        CmrRelay cmr = (CmrRelay) added.nextElement();
        UID contents = (UID) cmr.getContent();
        CmrRelay sentCmr = (CmrRelay) _sent.get(contents);
        if (sentCmr != null) {
          _sent.remove(contents);
          bbs.publishRemove(sentCmr);
          _log.debug("Received reply(" + contents + ") from " + cmr.getSource());
        } else if (_sent.get(cmr.getUID()) != null) {
          continue;
        } // end of if (_sent.get(cmr.getUID()) == null)
        
        bbs.publishRemove(cmr);
      	CmrRelay relay = (CmrRelay) 
      	  _cmrFactory.newCmrRelay(cmr.getUID(), cmr.getSource());
        _sent.put(relay.getUID(), relay);
        bbs.publishAdd(relay);
        _log.debug("Sending message(" + relay.getContent() + ") to " + relay.getTarget() + " from " + _agentId);
      } // end of while (added.hasMoreElements())
    } // end of if (_subscription.hasChanged())
    
  }

  protected void setupSubscriptions() {
    DomainService ds = getDomainService(); 
    _cmrFactory = (CmrFactory) ds.getFactory("cmr");
    _agentId = getAgentIdentifier();
    BlackboardService bbs = getBlackboardService();
    _subscription = (IncrementalSubscription) bbs.subscribe(_pred);

    if(_sendCount != -1) {
      Thread t = new Thread(new SendMsgTask());
      t.start();
    }
  }

  protected class SendMsgTask extends TimerTask {
    private Random _random = new Random();
    private int MAX_TRIES = 5;
    public void run() {
      BlackboardService bbs = getBlackboardService();
      try {
        //let's sleep for 2 min to get time for the society to start
        Thread.sleep(120 * 1000);
      }
      catch(Exception e) {
        e.printStackTrace(); 
      }
      for (int i = 0; i < _sendCount; i++) {
        MessageAddress agent = getRandomAgent();
        if (agent == null) {
          for (int j = 0; j < MAX_TRIES; j++) {
        	  agent = getRandomAgent();
        	}
        	if (agent == null) {
            _log.error("Can't get a random agent after " + MAX_TRIES + " times.");
            return;
          }
        }
      	CmrRelay relay = 
      	  _cmrFactory.newCmrRelay(_uidService.nextUID(), agent);
      	_sent.put(relay.getUID(), relay);
      	_log.debug("Sending initial message(" + relay.getUID() + ") to " + agent + " from " + _agentId);
      	bbs.openTransaction();
      	bbs.publishAdd(relay);
      	bbs.closeTransaction();
      	try {
          Thread.sleep(5 * 1000);  // let's sleep for 5 secs to allow for other agents to register
        }
        catch(Exception e) {
          e.printStackTrace(); 
        }
      } // end of for (int i = 0; i < _sentCount; i++)   
    }
    
    private MessageAddress getRandomAgent() {
      MessageAddress addr = null;
      try {
        NamingService  ns = (NamingService)
          _sb.getService(this, NamingService.class, null);
        NamingServerRegistry reg = new NamingServerRegistry(ns.getRootContext());
        String thisAgent = _agentId.toString();
        String agent = thisAgent;
        while(agent.equals(thisAgent)) {
          List agents = reg.listNames();
          agent = (String)agents.get(_random.nextInt(agents.size()));
          if(agent.equals(thisAgent)) {
            Thread.sleep(1000);
          }
        }
        _sb.releaseService(this, NamingService.class, ns);
        addr = new ClusterIdentifier(agent);
      }
      catch(Exception e) {
        e.printStackTrace(); 
      }
      return addr;
    }
  }
}
