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

package org.cougaar.core.security.crypto.crl.plugin;


import java.util.*;
// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.*;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.multicast.AttributeBasedAddress;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.core.util.UID;
import org.cougaar.core.service.community.*;


import org.cougaar.core.security.crypto.crl.blackboard.*;
import org.cougaar.core.security.services.crypto.*;


public class BBServicePlugin extends ComponentPlugin implements Runnable {

  // The domainService acts as a provider of domain factory services
  private DomainService domainService = null;
  private LoggingService loggingService=null;
  
  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService aDomainService) {
    domainService = aDomainService;
  }
  
  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
  }

 
  protected void setupSubscriptions() {
    loggingService = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
    Thread td=new Thread(this);
    td.start();
  }
   protected void execute () {
     
   }
  
  public void run() {
    BlackboardService bbs=getBlackboardService();
     CRLCacheService cacheservice= (CRLCacheService)getBindingSite().getServiceBroker().getService
      (this, CRLCacheService.class, null);
     if(cacheservice!=null)
       cacheservice.setBlackboardService(bbs);
    
  }
}
