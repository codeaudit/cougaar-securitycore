/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */


package org.cougaar.core.security.test.cm;


import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.cm.message.VerifyAgentAddRequest;
import org.cougaar.core.security.cm.message.VerifyResponse;
import org.cougaar.core.security.cm.relay.SharedDataRelay;
import org.cougaar.core.security.cm.service.CMService;
import org.cougaar.core.security.cm.service.CMServiceProvider;
import org.cougaar.core.service.LoggingService;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.util.UnaryPredicate;

import java.util.Enumeration;


/**
 * Plugin to test the CM. Subscribe to tasks published by the CMTestServlet.
 *
 * @author ttschampel
 */
public class CMTestPlugin extends ComponentPlugin {
  /** Logging Service */
  private LoggingService logging;
  /** Subscription to results from CM */
  private IncrementalSubscription subs = null;
  /** CMService */
  private CMService cmService = null;
  /** Predicate for CMResults */
  private UnaryPredicate predicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof SharedDataRelay) {
        SharedDataRelay sd = (SharedDataRelay) o;
        if ((sd.getResponse() != null) && sd.getResponse() instanceof VerifyResponse && (sd.getContent() != null) && sd.getContent() instanceof VerifyAgentAddRequest && ((VerifyAgentAddRequest) sd.getContent()).getAgent().equals(getAgentIdentifier().getAddress())) {
          return true;
        }
      }

      return false;
    }
  };

  /** Subscription to test cm tasks */
  private IncrementalSubscription testSubs = null;
  /** Predicate to test cm tasks */
  private UnaryPredicate testCMPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof Task) {
        Task t = (Task) o;
        if ((t.getVerb() != null) && t.getVerb().toString().equals(CMTestServlet.CM_TEST_VERB)) {
          return true;
        }
      }

      return false;
    }
  };

  /**
   * Set LoggingService
   *
   * @param service
   */
  public void setLoggingService(LoggingService service) {
    this.logging = service;
  }


  /**
   * load plugin
   */
  public void load() {
    super.load();

    cmService = (CMService) this.getServiceBroker().getService(this, CMService.class, null);
    if (cmService == null) {
      this.getServiceBroker().addService(CMService.class, new CMServiceProvider(getServiceBroker()));
      cmService = (CMService) this.getServiceBroker().getService(this, CMService.class, null);

    }
  }


  /**
   * Set up subscriptions
   */
  public void setupSubscriptions() {
    this.subs = (IncrementalSubscription) this.getBlackboardService().subscribe(predicate);
    this.testSubs = (IncrementalSubscription) this.getBlackboardService().subscribe(this.testCMPredicate);

  }


  /**
   * process subscriptions
   */
  public void execute() {
    Enumeration testEnumeration = testSubs.getAddedList();
    while (testEnumeration.hasMoreElements()) {
      Task task = (Task) testEnumeration.nextElement();
      String moveToNode = (String) task.getPrepositionalPhrase(CMTestServlet.DEST_NODE_PREP).getIndirectObject();
      VerifyAgentAddRequest request = new VerifyAgentAddRequest(moveToNode, this.getAgentIdentifier().getAddress());
      cmService.sendMessage(request, getBlackboardService());
    }

    Enumeration enumeration = subs.getChangedList();
    while (enumeration.hasMoreElements()) {
      SharedDataRelay relay = (SharedDataRelay) enumeration.nextElement();
      VerifyResponse response = (VerifyResponse) relay.getResponse();
      if (logging.isInfoEnabled()) {
        logging.info("CM Response:" + response.getValidRequest());
      }
    }
  }
}
