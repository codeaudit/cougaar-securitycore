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
