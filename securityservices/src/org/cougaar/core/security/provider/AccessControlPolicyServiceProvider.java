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

// Cougaar core services
import org.cougaar.core.component.*;
import org.cougaar.util.*;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.crypto.KeyRing;
import org.cougaar.core.security.certauthority.KeyManagement;
import org.cougaar.core.security.access.AccessControlPolicyServiceImpl;
import org.cougaar.core.security.crypto.AgentIdentityServiceImpl;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.services.acl.*;
import org.cougaar.core.security.services.identity.*;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

public class AccessControlPolicyServiceProvider 
  implements ServiceProvider
{
  private KeyRingService keyRing;
  private SecurityPropertiesService sps;
  private static AccessControlPolicyService accessControlPolicyService;
  private ServiceBroker theBroker;

  public AccessControlPolicyServiceProvider(ServiceBroker broker){
    theBroker = broker;
  }
  /**
   * Get a service.
   * @param sb a Service Broker
   * @param requestor the requestor of the service
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @return a service
   */
  public synchronized Object getService(ServiceBroker sb, 
					Object requestor, 
					Class serviceClass) {
    LoggingService log = (LoggingService)
      sb.getService(this,
		    LoggingService.class, null);
    if (accessControlPolicyService == null) {
      accessControlPolicyService =
	new AccessControlPolicyServiceImpl(theBroker);
    }
    if (log.isDebugEnabled()) {
      log.debug("AC policy Service Request: "
			 + requestor.getClass().getName()
			 + " - " + serviceClass.getName()
			 + " - service: " + accessControlPolicyService);
    }

    return accessControlPolicyService;
  }

  /** Release a service.
   * @param sb a Service Broker.
   * @param requestor the requestor of the service.
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @param service the service to be released.
   */
  public void releaseService(ServiceBroker sb,
			     Object requestor,
			     Class serviceClass,
			     Object service) {
  }
}
