/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
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

package test.org.cougaar.core.security.simul;

import org.cougaar.core.component.*;
import org.cougaar.core.agent.*;
import org.cougaar.core.mts.*;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.util.*;
import java.lang.reflect.*;
import org.cougaar.core.security.services.util.PolicyBootstrapperService;

import safe.guard.NodeGuard;

/**
 * "default" security manager for integration work.
 * Supports old properties org.cougaar.core.security.manager and org.cougaar.manager for
 * backward compatability.
 * @property org.cougaar.core.security.Domain
 *   The security domain ID to use for the StandardSecurityManager.
 **/

public final class GuardFactory
{
  public final static String PROP_PREFIX = "org.cougaar.core.security";
  public final static String SMC_PROP = PROP_PREFIX+".Component";
  public final static String SMD_PROP = PROP_PREFIX+".Domain";

  protected Object guard = null;
  private ServiceBroker serviceBroker = null;
  protected MessageTransportService mts = null;
  private boolean isActivated = false;

  public GuardFactory(ServiceBroker sb) {
    serviceBroker = sb;
    init();
  }

  public synchronized final void setMessageTransportService(MessageTransportService mts) {
    if (this.mts == null && mts != null) {
      this.mts = mts;
      maybeActivate();
    }
  }
 
  public void init() {
    String dmId = System.getProperty(SMD_PROP);
  
    serviceBroker.addServiceListener(new ServiceAvailableListener() {
        public void serviceAvailable(ServiceAvailableEvent ae) {
          Class sc = ae.getService();
          if (MessageTransportService.class.isAssignableFrom(sc)) {
            Object ts = serviceBroker.getService(GuardFactory.this, MessageTransportService.class, null);
            if (ts instanceof MessageTransportService) {
              GuardFactory.this.setMessageTransportService((MessageTransportService)ts);
              maybeActivate();
            }
          }
        }
      });

    if (dmId == null) {
      //System.err.println("System property "+SMD_PROP+" not set.\nProceeding without Guard!");
    } else {
      System.err.println("Creating Guard");
      try {
	PolicyBootstrapperService pbs = (PolicyBootstrapperService)
	  serviceBroker.getService(this, PolicyBootstrapperService.class, null);

	String policyManagerUIC = "UniqueID";
	ServiceBroker rootServiceBroker = serviceBroker;
	guard = new NodeGuard(policyManagerUIC, dmId, serviceBroker,
			      rootServiceBroker);
        
        System.out.println("Initializing Guard.");
	boolean isInitialized = false; // ((NodeGuard)guard).initialize(dmId, );
	System.out.println("Guard initialization status: " + isInitialized);
      } catch (Exception e) {
        System.err.println("ERROR!: while loading NodeGuard: " + e);
	e.printStackTrace();
      }
    }
    
    maybeActivate();
  }
  
  protected synchronized void maybeActivate() {
    if (!isActivated) {
      if (guard != null && mts != null) {
        System.err.println("Activating Guard");
        try {
          Method gsmt = guard.getClass()
            .getMethod("setMessageTransport", new Class[] { MessageTransportService.class });
          gsmt.invoke(guard, new Object[] { mts } );
        } catch (Exception e) {
          e.printStackTrace();
          System.exit(0);
        }
        isActivated = true;
      }
    }
  }

}
