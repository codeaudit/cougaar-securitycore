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

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.util.UID;
import org.cougaar.util.UnaryPredicate;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

public class BouncePlugin extends ComponentPlugin {
  /**
   * for set/get DomainService
   */
  protected DomainService  _domainService;


  private LoggingService  _log;
  private Hashtable       _sent = new Hashtable();
  private UnaryPredicate  _pred = new UnaryPredicate() {
      public boolean execute(Object obj) {
        return (obj instanceof CmrRelay &&
                ((CmrRelay) obj).getContent() instanceof UID);
      }
    };
  private IncrementalSubscription _subscription;
  private MessageAddress _destination;

  private CmrFactory _cmrFactory;
  private String     _id;
  private int        _sendCount = 10;

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
    System.out.println("setParameter called with: " + o);
    Thread.dumpStack();
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;
    Object[] arr = l.toArray();
    if (arr.length != 0) {
      _id = arr[0].toString();
    }
    if (arr.length > 1) {
      _destination =  MessageAddress.getMessageAddress(arr[1].toString());
    }
    if (arr.length > 2) {
      _sendCount = Integer.parseInt(arr[2].toString());
    } // end of else
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
        } else if (_sent.get(cmr.getUID()) != null) {
          continue;
        } // end of if (_sent.get(cmr.getUID()) == null)
        
        bbs.publishRemove(cmr);
        Object o = cmr.getUID();

	MessageAddress ci = null;
	if (_destination != null) {
	  ci = _destination;
	}
	else {
	  ci = cmr.getSource();
	}
	CmrRelay relay = (CmrRelay) _cmrFactory.newCmrRelay(o, ci);
        _sent.put(relay.getUID(), relay);
        bbs.publishAdd(relay);
      } // end of while (added.hasMoreElements())
    } // end of if (_subscription.hasChanged())
    
  }

  /**
   * Sets up the AggregationQuery and event subscriptions.
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);

    BlackboardService bbs = getBlackboardService();

    _subscription = (IncrementalSubscription) bbs.subscribe(_pred);

    DomainService        ds           = getDomainService(); 
    _cmrFactory                        = (CmrFactory) ds.getFactory("cmr");

    if (_id != null && _destination != null) {
      for (int i = 0; i < _sendCount; i++) {
	UID uid = new UID(_id, i);
	CmrRelay relay = _cmrFactory.newCmrRelay(uid, _destination);
	_sent.put(relay.getUID(), relay);
	bbs.publishAdd(relay);
      } // end of for (int i = 0; i < _sent.length; i++)
    }
  }

}
