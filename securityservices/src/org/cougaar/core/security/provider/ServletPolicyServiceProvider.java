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

// Cougaar core services
import org.cougaar.core.component.*;
import org.cougaar.util.*;

// Cougaar security services
import org.cougaar.core.security.acl.auth.ServletPolicyEnforcer;
import org.cougaar.core.security.services.crypto.ServletPolicyService;
import org.cougaar.core.security.acl.auth.DualAuthenticator;

// Tomcat 4.0 
import org.apache.catalina.Context;

public class ServletPolicyServiceProvider 
  implements ServiceProvider
{
  static private ServletPolicyEnforcer _servletPolicyService = null;
  static private ServiceBroker serviceBroker;

  public ServletPolicyServiceProvider(ServiceBroker sb) {
    serviceBroker = sb;
  }

  public static synchronized void setContext(Context context) {
    if (_servletPolicyService == null) {
      _servletPolicyService = new ServletPolicyEnforcer(serviceBroker);
    }
    _servletPolicyService.setContext(context);
  }

  public static synchronized void setDualAuthenticator(DualAuthenticator da) {
    if (_servletPolicyService == null) {
      _servletPolicyService = new ServletPolicyEnforcer(serviceBroker);
    }
    _servletPolicyService.setDualAuthenticator(da);
  }

  public Object getService(ServiceBroker sb, 
                           Object requestor, 
                           Class serviceClass) {
    return _servletPolicyService;
  }
  public void releaseService(ServiceBroker sb,
			     Object requestor,
			     Class serviceClass,
			     Object service) {
  }
}
