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
  extends BaseSecurityServiceProvider
{
  static private ServletPolicyEnforcer _servletPolicyService = null;
  static private DualAuthenticator     _dualAuthenticator    = null;
  static private Context               _context              = null;
  static private ServiceBroker         _staticServiceBroker  = null;

  public ServletPolicyServiceProvider(ServiceBroker sb, String community) {
    super(sb, community);
    _staticServiceBroker = sb;
  }

  private static synchronized void init() {
    if (_servletPolicyService == null) {
      _servletPolicyService = new ServletPolicyEnforcer(_staticServiceBroker);
      if (_dualAuthenticator != null) {
        _servletPolicyService.setDualAuthenticator(_dualAuthenticator);
      }
      if (_context != null) {
        _servletPolicyService.setContext(_context);
      }
    }
  }

  public static void addAgent(String agent) {
    init();
    _servletPolicyService.addAgent(agent);
  }

  public static synchronized void setContext(Context context) {
    init();
    _context = context;
    if (_servletPolicyService != null) {
      _servletPolicyService.setContext(context);
    }
  }

  public static synchronized void setDualAuthenticator(DualAuthenticator da) {
    init();
    _dualAuthenticator = da;
    if (_servletPolicyService != null) {
      _servletPolicyService.setDualAuthenticator(da);
    }
  }

  /**
   * Get a service.
   * @param sb a Service Broker
   * @param requestor the requestor of the service
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @return a service
   */
  protected Service getInternalService(ServiceBroker sb, 
				       Object requestor, 
				       Class serviceClass) {
    return _servletPolicyService;
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
