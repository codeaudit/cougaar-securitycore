/*
 * <copyright>
 *  Copyright 1997-2003 Networks Associates Technology, Inc.
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
 */
package org.cougaar.core.security.provider;

// Cougaar core services
import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.dataprotection.PersistenceMgrPolicyServiceImpl;
import org.cougaar.core.security.services.util.PersistenceMgrPolicyService;

public class PersistenceMgrPolicyServiceProvider 
  extends BaseSecurityServiceProvider
{
  // singleton 
  private PersistenceMgrPolicyService _instance;
  // the security community of this node
  private String _myCommunity;
  private ServiceBroker _serviceBroker;
  
  public PersistenceMgrPolicyServiceProvider(ServiceBroker sb, String community) {
    super(sb, community);
    _serviceBroker = sb;
    _myCommunity = community;
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
    if(_instance == null) {
      _instance = new PersistenceMgrPolicyServiceImpl(_serviceBroker, _myCommunity);
    }
    return _instance;
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
  }
}
