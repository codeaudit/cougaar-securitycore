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

// Cougaar core infrastructure
import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceRevokedEvent;
import org.cougaar.core.component.ServiceRevokedListener;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.ssl.WebserverSSLServiceImpl;

public class WebserverSSLServiceProvider
  extends BaseSecurityServiceProvider
{
  private KeyRingService ksr;

  static private WebserverSSLServiceImpl sslservice = null;

  public WebserverSSLServiceProvider(ServiceBroker sb, String community) {
    super(sb, community);
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

    if (sslservice != null)
      return sslservice;

    // Retrieve KeyRing service
    ksr = (KeyRingService)
      sb.getService(requestor,
		    KeyRingService.class,
		    new ServiceRevokedListener() {
			public void serviceRevoked(ServiceRevokedEvent re) {
			  if (KeyRingService.class.equals(re.getService()))
			    ksr  = null;
			}
		      });

    try {
      sslservice = new WebserverSSLServiceImpl(sb);
      sslservice.init(ksr);
    }
    catch (Exception e) {
      if (log.isDebugEnabled())
        log.debug("Failed to initialize WebserverSSLService! " + e.toString());
    }
    return sslservice;
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
