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
import org.cougaar.core.component.*;
import org.cougaar.util.*;

// Cougaar security services
import org.cougaar.core.security.util.CryptoDebug;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.services.identity.*;
import org.cougaar.core.security.ssl.*;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

public class WebserverSSLServiceProvider
  implements ServiceProvider {
  private KeyRingService ksr;

  static private WebserverSSLServiceImpl sslservice = null;

  public Object getService(ServiceBroker sb,
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
      sslservice = new WebserverSSLServiceImpl();
      sslservice.init(ksr);
    }
    catch (Exception e) {
      System.out.println("Failed to initialized WebserverSSLService!");
    }
    return sslservice;
  }

  public void releaseService(ServiceBroker sb,
			     Object requestor,
			     Class serviceClass,
			     Object service) {
  }
}
