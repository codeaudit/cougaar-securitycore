/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

package org.cougaar.core.security.certauthority;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.service.BlackboardQueryService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.servlet.SimpleServletSupportImpl;

import javax.servlet.Servlet;

public class SecurityServletSupportImpl
  extends SimpleServletSupportImpl
  implements SecurityServletSupport
{
  private SecurityPropertiesService securityPropertiesService;
  //private CertificateManagementService certificateManagementService;
  private ServiceBroker serviceBroker;
  //private NamingService ns;
  
  public SecurityServletSupportImpl(String path,
				    MessageAddress agentId,
				    BlackboardQueryService blackboard,
				    ServiceBroker sb,
				    LoggingService log) {
    super(path, agentId, blackboard, log);
    //super(path, agentId, blackboard, ns, log);
    serviceBroker = sb;
  }

  public SecurityPropertiesService getSecurityProperties(Servlet servlet) {
    // Get the security properties service
    securityPropertiesService = (SecurityPropertiesService)
      serviceBroker.getService(
	servlet,
	SecurityPropertiesService.class,
	null);
    if (securityPropertiesService == null) {
      throw new RuntimeException(
	"Unable to obtain security properties service");
    }
    return securityPropertiesService;
  }

  public ServiceBroker getServiceBroker() {
    return serviceBroker;
  }
}
