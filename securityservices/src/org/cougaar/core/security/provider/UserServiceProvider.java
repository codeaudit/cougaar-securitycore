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

import java.util.*;
import javax.naming.NamingException;

// Cougaar core infrastructure
import org.cougaar.core.component.ServiceProvider;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.Service;
import org.cougaar.core.service.AgentIdentificationService;


// Cougaar security services
import org.cougaar.core.security.services.acl.UserService;
import org.cougaar.core.security.acl.user.AgentUserService;
import org.cougaar.core.security.acl.user.LdapUserServiceImpl;
import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.services.acl.UserService;
import org.cougaar.core.security.acl.user.AgentUserService;
import org.cougaar.core.mts.MessageAddress;


public class UserServiceProvider implements ServiceProvider
{
  private static final boolean AGENT_SERVICE = !Boolean.getBoolean("org.cougaar.core.security.provider.UserService.ldap");
  private UserService       _service;
  private MessageAddress    _agent;

  public UserServiceProvider(MessageAddress agent) {
    _agent = agent;
  }

  public UserServiceProvider(ServiceBroker root) {
    if (!AGENT_SERVICE) {
      LdapUserServiceImpl.setRootServiceBroker(root);
    }
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
    if (_service == null) {
      if (_agent == null) {
        AgentIdentificationService ais = (AgentIdentificationService)
          sb.getService(this, AgentIdentificationService.class, null);
        _agent = ais.getMessageAddress();
      }
      if (AGENT_SERVICE) {
        _service = new AgentUserService(sb, _agent);
      } else {
        _service = new LdapUserServiceImpl(sb, _agent);
      }
    }
    return _service;
  }

  /** Release a service.
   * @param sb a Service Broker.
   * @param requestor the requestor of the service.
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @param service the service to be released.
   */
  public synchronized void releaseService(ServiceBroker sb,
                                             Object requestor,
                                             Class serviceClass,
                                             Object service) {
  }
}
