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
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.util.SecurityPropertiesServiceImpl;

import java.util.Hashtable;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;

public class SecurityPropertiesServiceProvider
  extends BaseSecurityServiceProvider
{
  /** A hashtable containing all the servlet context instances */
  static private Hashtable contextMap;
  /** A singleton service to use when servlet context is null. */
  static private SecurityPropertiesService secProp;

  public SecurityPropertiesServiceProvider(ServiceBroker sb, String community) {
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
    SecurityPropertiesService securityPropertiesService = null;
    // Instantiate one service for each servlet context
    javax.servlet.ServletContext context = null;

    if (requestor instanceof Servlet) {
      Servlet servlet = (Servlet) requestor;
      ServletConfig config = servlet.getServletConfig();
      if (config != null) {
	context = config.getServletContext();
      }
    }
    if (context == null) {
      if (secProp == null) {
	secProp = new SecurityPropertiesServiceImpl(sb);
      }
      securityPropertiesService = secProp;
    }
    else {
      // Figure out if the service has already been instantiated
      // for that context.
      securityPropertiesService =
	(SecurityPropertiesService)contextMap.get(context);
      if (securityPropertiesService == null) {
	securityPropertiesService =
	  new SecurityPropertiesServiceImpl(context, sb);
	contextMap.put(context, securityPropertiesService);
      }
    }
    return securityPropertiesService;
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
