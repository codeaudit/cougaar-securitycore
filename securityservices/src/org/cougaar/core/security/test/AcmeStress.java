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
import org.cougaar.core.service.EventService;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

public class AcmeStress extends ComponentPlugin {
  /**
   * for set/get DomainService
   */
  protected DomainService  _domainService;
  private EventService   _eventService;
  private LoggingService  _log;
  private int        _sendCount;
  private int        _sleepDelay;

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
    //    Thread.dumpStack();
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;
    Object[] arr = l.toArray();
    System.out.println("argument array = " + arr + " with length " + arr.length);

    if (arr.length != 0) {
      _sleepDelay = Integer.parseInt(arr[0].toString());
      System.out.println("_sleepDelay = " + _sleepDelay);
    }
  }

  protected void execute() {
  }

  /**
   * Sets up the AggregationQuery and event subscriptions.
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);

    _eventService = (EventService)getServiceBroker().getService
      (this, EventService.class, null);

    for (int i = 0 ;; i++) {
      StringBuffer buf = new StringBuffer();
      buf.append("[STATUS] SecurityManager(");
      buf.append("Addr");
      buf.append(") Analyzer(");
      buf.append("analyzerID");
      buf.append(") Operation(");
      buf.append("234234");
      buf.append(") Classifications(");
      buf.append(i);
      buf.append(")");
      _eventService.event(buf.toString());
      System.out.println("Event " + i);
      try {
        Thread.sleep(_sleepDelay);
      }
      catch (java.lang.InterruptedException e) {}
    }
  }

}
