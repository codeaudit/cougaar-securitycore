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

import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.access.AccessControlPolicyServiceImpl;
import org.cougaar.core.security.access.AccessPolicyClient;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

import java.util.HashMap;

public class AccessControlPolicyServiceProvider 
  extends BaseSecurityServiceProvider
{
  private KeyRingService keyRing;
  private SecurityPropertiesService sps;
  private HashMap agentList = new HashMap();

  public AccessControlPolicyServiceProvider(ServiceBroker sb, String community) {
    super(sb, community);
  }

  /**
   * Get a service.
   * @param sb a Service Broker
   * @param requestor the requestor of the service
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @return a service
   */
  protected synchronized Service getInternalService(ServiceBroker sb, 
						    Object requestor, 
						    Class serviceClass) {
    String name;
    try {
      AccessPolicyClient apc = (AccessPolicyClient)requestor;
      name = apc.getName();
    } catch(Exception e) {
      //the cast failed, not an access agent binder, no service.
      log.error("Only AccessPolicyClient is allowed to request for the service.");
      return null;
    }
    Object o = agentList.get(name);
    if (o == null) {
      o = new AccessControlPolicyServiceImpl(serviceBroker, name);
      agentList.put(name, o);
    }
    if (log.isDebugEnabled()) {
      log.debug("AC policy Service Request: "
		+ requestor.getClass().getName()
		+ " - " + serviceClass.getName());
    }

    return (Service)o;
  }

  /** Release a service.
   * @param sb a Service Broker.
   * @param requestor the requestor of the service.
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @param service the service to be released.
   */
  protected void releaseInternalService(ServiceBroker sb,
					Object requestor,
					Class serviceClass,
					Object service) {
    String name = null;
    try {
      AccessPolicyClient apc = (AccessPolicyClient)requestor;
      name = apc.getName();
    } catch(Exception e) {
      log.error("Unable to release service:" + e);
    }
    if (name!=null) {
      agentList.remove(name);
    }
  }
}
