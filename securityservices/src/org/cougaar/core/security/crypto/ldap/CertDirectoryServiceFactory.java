/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package org.cougaar.core.security.crypto.ldap;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.policy.*;

public class CertDirectoryServiceFactory
{
  //private static boolean log.isDebugEnabled() = false;

  public static CertDirectoryServiceClient getCertDirectoryServiceClientInstance(
					      int serverType, String serverUrl, ServiceBroker sb)
  {
    LoggingService log = (LoggingService)
      sb.getService(new CertDirectoryServiceFactory(),
		    LoggingService.class, null);
    CertDirectoryServiceClient ldapClient = null;
    switch (serverType) {
    case TrustedCaPolicy.COUGAAR_OPENLDAP:
      ldapClient = new OpenLdapCertDirectoryService(serverUrl, sb);
      break;
    case TrustedCaPolicy.NETTOOLS:
      ldapClient = new NetToolsCertDirectoryService(serverUrl, sb);
      break;
    default:
      if (log.isWarnEnabled()) {
	log.warn("Client: Unknown directory service type: " + serverType);
      }
    }
    return ldapClient;
  }

  public static CertDirectoryServiceCA getCertDirectoryServiceCAInstance(
					      int serverType, String serverUrl,
					      ServiceBroker sb)
  {
    CertDirectoryServiceCA instance = null;
    LoggingService log = (LoggingService)
      sb.getService(new CertDirectoryServiceFactory(),
		    LoggingService.class, null);

    switch (serverType) {
    case TrustedCaPolicy.COUGAAR_OPENLDAP:
      instance = new OpenLdapCertDirectoryService(serverUrl, sb);
      break;
    default:
      // Net Tools does not support CA functions programmatically.
      if (log.isDebugEnabled()) {
	log.debug("CA: Unknown directory service type: " + serverType);
      }
    }
    return instance;
  }
}








