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

import java.security.PrivilegedAction;
import java.security.AccessController;

// Cougaar core services
import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

// Cougaar security services
import org.cougaar.core.security.auth.SecurityContextServiceImpl;
import org.cougaar.core.security.auth.ObjectContextUtil;
import org.cougaar.core.security.services.auth.SecurityContextService;

public class SecurityContextServiceProvider 
  extends BaseSecurityServiceProvider
{
  // singleton
  private static SecurityContextService _instance;
  
  private static synchronized void setService(final ServiceBroker sb) {
    if (_instance != null) {
      return;
    }
    _instance = new SecurityContextServiceImpl(sb);
    PrivilegedAction setService = new PrivilegedAction() {
        public Object run() {
          try {
            ObjectContextUtil.setContextService(_instance);
          } catch (Exception e) {
            LoggingService log = 
              (LoggingService) sb.getService(this, LoggingService.class, null);
            log.warn("Could not call ObjectContextUtil" +
                     ".setContextService()", e);
            sb.releaseService(this, LoggingService.class, log);
          }
          return null;
        }
      };
    AccessController.doPrivileged(setService);
  }

  public SecurityContextServiceProvider(ServiceBroker sb, 
                                        String community) {
    super(sb, community);
    setService(sb);
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
