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
import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServlet;

// Cougaar core services
import org.cougaar.core.component.*;
import org.cougaar.util.*;

// Cougaar security services
import org.cougaar.core.security.util.CryptoDebug;
import org.cougaar.core.security.util.SecurityPropertiesServiceImpl;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

public class SecurityPropertiesServiceProvider
  implements ServiceProvider
{
  /** A hashtable containing all the servlet context instances
   */
  static private Hashtable contextMap;
  /** A singleton service to use when servlet context is null.
     */
  static private SecurityPropertiesService secProp;
  public synchronized Object getService(ServiceBroker sb, 
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
	secProp = new SecurityPropertiesServiceImpl();
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
	  new SecurityPropertiesServiceImpl(context);
	contextMap.put(context, securityPropertiesService);
      }
    }
    return securityPropertiesService;
  }

  public void releaseService(ServiceBroker sb,
			     Object requestor,
			     Class serviceClass,
			     Object service) {
  }
}
