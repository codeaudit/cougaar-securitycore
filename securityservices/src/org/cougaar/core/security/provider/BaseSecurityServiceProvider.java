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

package org.cougaar.core.security.provider;

import java.lang.*;
import java.util.Hashtable;

// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceProvider;
import org.cougaar.core.component.Service;

// Cougaar security services
import org.cougaar.core.security.provider.SecurityServicePermission;
import org.cougaar.core.security.util.*;

public abstract class BaseSecurityServiceProvider
  implements ServiceProvider
{
  protected LoggingService log;
  protected ServiceBroker serviceBroker;
  protected String mySecurityCommunity;

  public BaseSecurityServiceProvider(ServiceBroker sb, String community) {
    serviceBroker = sb;
    mySecurityCommunity = community;
    log = (LoggingService)
      sb.getService(this, LoggingService.class, null);
  }

  /** **********************************************************************
   * ServiceProvider Interface
   */
  public Object getService(ServiceBroker sb,
			   Object requestor,
			   Class serviceClass) {
    if (log.isDebugEnabled()) {
      log.debug("Security Service Request: "
		+ requestor.getClass().getName()
		+ " - " + serviceClass.getName());
    }
    if (sb == null) {
      if (log.isWarnEnabled()) {
	log.warn("Running in a test environment");
      }
      sb = serviceBroker;
    }
    SecurityManager security = System.getSecurityManager();
    if (serviceClass == null) {
      throw new IllegalArgumentException("Illegal service class");
    }
    if(security != null) {
      log.debug("Checking Security Permission for :"+serviceClass.getName()+
		"\nRequestor is "+requestor.getClass().getName());
      security.checkPermission(new SecurityServicePermission(serviceClass.getName()));
    }
    Service service = null;
    try {
      service = getInternalService(sb, requestor, serviceClass);
    }
    catch (Exception e) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to get service request for " + serviceClass.getName() + ": " + e);
      }
    }
    if (service == null) {
      if (log.isWarnEnabled()) {
	log.warn("Service not registered: " + serviceClass.getName()
	  + " Requestor:" + requestor.getClass().getName());
      }
    }
    return service;
  }

  public void releaseService(ServiceBroker sb,
			     Object requestor,
			     Class serviceClass,
			     Object service) {
    releaseInternalService(sb, requestor, serviceClass, service);
  }

  /** **********************************************************************
   * End ServiceProvider Interface
   */

  protected abstract Service getInternalService(ServiceBroker sb, 
						Object requestor, 
						Class serviceClass);

  protected abstract void releaseInternalService(ServiceBroker sb,
						 Object requestor,
						 Class serviceClass,
						 Object service);
}
