/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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

import java.util.Enumeration;
import java.util.HashSet;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.LoggingService;
import org.cougaar.servicediscovery.description.ServiceContract;
import org.cougaar.servicediscovery.transaction.ServiceContractRelay;
import org.cougaar.util.UnaryPredicate;

public class ServiceContractReaderPlugin extends ComponentPlugin {

  private LoggingService          _log;
  private String                  _agentName;
  private IncrementalSubscription _issc;


  private UnaryPredicate _scPredicate = new UnaryPredicate() {
      private HashSet  seen = new HashSet();

      public boolean execute(Object o) {
        String classname = o.getClass().getName();
        if (!seen.contains(classname)) {
          _log.debug("new blackboard object = " + classname);
          seen.add(classname);
        }
        return (o instanceof ServiceContractRelay);
      }
    };


  protected void setupSubscriptions()
  {
    try {
	BindingSite bs = getBindingSite();
	ServiceBroker sb = bs.getServiceBroker();

        _log = (LoggingService) sb.getService(this,
                                              LoggingService.class,
                                              null);
        _log.debug("setting up subscriptions");
        _issc = (IncrementalSubscription) blackboard.subscribe(_scPredicate);
        _agentName = getAgentIdentifier().toAddress();

    } catch (Exception e) {
      _log.fatal(".InitAgentPlugin: Error initializing agent policy plugin",
                 e);
    }
  }

  protected void execute()
  {
    for (Enumeration added = _issc.getAddedList();
         added.hasMoreElements();) {
      ServiceContractRelay  scr = (ServiceContractRelay) added.nextElement();
      String receiver = scr.getProviderName();
      ServiceContract sc  = scr.getServiceContract();
      if (sc != null) {
        _log.debug("Interception: ServiceContractRelay : " + _agentName + " : <-> : " 
                   + receiver + ": " 
                   +  sc.getServiceRole());
      } else {
        _log.debug("why is the service contract null");
      }
    }
  }
}
