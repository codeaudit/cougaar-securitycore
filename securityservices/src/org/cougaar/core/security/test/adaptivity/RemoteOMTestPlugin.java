/*
 * <copyright>
 *  Copyright 1997-2002 Networks Associates Inc
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
package org.cougaar.core.security.test.adaptivity;


import org.cougaar.core.adaptivity.InterAgentOperatingMode;
import org.cougaar.core.adaptivity.InterAgentOperatingModePolicy;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.adaptivity.OperatingModeImpl;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ServiceUserPlugin;
import org.cougaar.core.service.UIDService;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Iterator;

/**
 * Publishes an inter agent operating mode to be controlled by 
 * another agent adaptivity engine.
 */
public class RemoteOMTestPlugin extends ServiceUserPlugin {

  private final static String REMOTEOM = "RemoteOMTestPlugin.REMOTE_OPERATING_MODE";
  private IncrementalSubscription remoteOMSubscription;
  private IncrementalSubscription remoteOMPSubscription;
  //private InterAgentOperatingMode remoteOM;
  private OperatingMode remoteOM;
  //private LoggingService logger;
  private UIDService uidService;
  
  private static Double[] values = {
        new Double(  1),
        new Double(  2),
        new Double(  4),
        new Double(  8),
        new Double( 16),
        new Double( 32),
        new Double( 64),
        new Double(128),
        new Double(256),
        new Double(512),
    };

  private UnaryPredicate remoteOMPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof OperatingMode) {
        OperatingMode om = (OperatingMode) o; 
        String omName = om.getName();
        if (REMOTEOM.equals(omName)) {
          return true;
        }
      }
      return false;
    }
  };      
  
  private UnaryPredicate remoteOMPPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof InterAgentOperatingModePolicy) {
          return true;
      }
      return false;
    }
  };
  
  private static final Class[] requiredServices = {
    UIDService.class
  };

  public RemoteOMTestPlugin() {
    super(requiredServices);
  }
  
  public void setupSubscriptions() {
    remoteOM = new OperatingModeImpl( REMOTEOM, new OMCRangeList(values), new Double(1));
    remoteOMSubscription = (IncrementalSubscription)blackboard.subscribe(remoteOMPredicate);
    remoteOMPSubscription = (IncrementalSubscription)blackboard.subscribe(remoteOMPPredicate);
    blackboard.publishAdd(remoteOM);
    if(haveServices()) { 
      logger.debug("##### obtained services #####");
     }
  }
  
  public void execute() {
    if (remoteOMSubscription.hasChanged()) {
      Collection oms = remoteOMSubscription.getChangedCollection();
      Iterator i = oms.iterator();
      OperatingMode om = null;
      if(oms != null && oms.size() > 0) {
        Object o = i.next();
        om = (OperatingMode)o;
        logger.debug(om.getName() + " has changed to " +  om.getValue() + ".");
        if( o instanceof InterAgentOperatingMode ) {
          InterAgentOperatingMode iaom = (InterAgentOperatingMode)o;
          logger.debug("this is an inter agent operating mode with source: " +  iaom.getSource());
        }
      }
      else {
        logger.error("remoteOMSubscription.getChangedCollection() returned collection of size 0!");
      }
    }
    if(remoteOMPSubscription.hasChanged()) {
      Collection oms = remoteOMPSubscription.getChangedCollection();
      Iterator i = oms.iterator();
      InterAgentOperatingModePolicy iaomp = null;
      
      if(oms != null && oms.size() > 0) {
        iaomp = (InterAgentOperatingModePolicy)i.next();
        logger.debug("received inter agent operating mode policy from: " + iaomp.getSource());
      }
      else {
        logger.error("remoteOMPSubscription.getChangedCollection() returned collection of size 0!");
      }
    }
  }
  
  private boolean haveServices() {
    if (uidService != null) return true;
    if (acquireServices()) {
      ServiceBroker sb = getServiceBroker();
      uidService = (UIDService)
        sb.getService(this, UIDService.class, null);
      return true;
    }
    return false;
  }

}
