/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package org.cougaar.core.security.dataprotection.plugin;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.dataprotection.DataProtectionKeyUnlockRequest;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Iterator;

class DataProtectionKeyRequestPredicate
  implements UnaryPredicate
{
  public boolean execute(Object o) {
    if (o instanceof DataProtectionKeyUnlockRequest) {
      return true;
    }
    return false;
  }
}

public class PersistenceMgrPlugin
  extends ComponentPlugin
{
  /** The logging service. */
  private LoggingService log;
  private KeyRecoveryRequestHandler requestHandler;

  /** Subscription that contains all requests to unlock data protection keys. */
  private IncrementalSubscription unlockRequestsSubscription;

  public void setParameter(Object o) {
  }

  protected void setupSubscriptions() {
    log = (LoggingService)
      getBindingSite().getServiceBroker().getService(this,
						     LoggingService.class, null);
    if (log.isDebugEnabled()) {
      log.debug("setupSubscriptions");
    }

    requestHandler = new KeyRecoveryRequestHandler(getBindingSite().getServiceBroker(),
						   getAgentIdentifier());

    // Subscribe to all requests to unlock data protection keys
    unlockRequestsSubscription = (IncrementalSubscription)getBlackboardService().subscribe
      (new DataProtectionKeyRequestPredicate());

  }

  public void execute() {
    if (log.isDebugEnabled()) {
      log.debug("execute");
    }
    Collection requestCollection = unlockRequestsSubscription.getAddedCollection();
    Iterator it = requestCollection.iterator();
    while (it.hasNext()) {
      DataProtectionKeyUnlockRequest request = (DataProtectionKeyUnlockRequest)it.next();
      log.debug("received request: " + request.toString());
      requestHandler.processKeyRecoveryRequest(request);
      // need to change the source and target
      Object response = request.getResponse();
      if (response == null) {
        log.debug("The response is empty.");
        continue;
      }
      log.debug("recovered request: " + request.toString());
      getBlackboardService().publishChange(request);
    }
  }
}
