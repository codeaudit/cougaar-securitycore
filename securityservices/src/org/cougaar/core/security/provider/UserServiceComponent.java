/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
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

package org.cougaar.core.security.provider;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.*;
import org.cougaar.core.agent.*;
import org.cougaar.core.mts.*;
import org.cougaar.core.security.services.acl.UserService;
import org.cougaar.util.*;
import org.cougaar.core.component.ComponentSupport;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.security.provider.UserServiceProvider;

public class UserServiceComponent extends ComponentSupport
{
  AgentIdentificationService _ais;

  public UserServiceComponent() {
  }

  public void setAgentIdentificationService(AgentIdentificationService ais) {
    _ais = ais;
  }

  public void load() {
    super.load();
    MessageAddress agent = _ais.getMessageAddress();
    ServiceBroker sb = getServiceBroker();
    sb.addService(UserService.class, new UserServiceProvider(agent));
  }
}
