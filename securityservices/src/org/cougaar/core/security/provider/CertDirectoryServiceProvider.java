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

package org.cougaar.core.security.provider;

import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.blackboard.CACertDirectoryServiceImpl;
import org.cougaar.core.security.crypto.ldap.NetToolsCertDirectoryService;
import org.cougaar.core.security.crypto.ldap.OpenLdapCertDirectoryServiceImpl;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceCA;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;
import org.cougaar.core.security.services.util.CACertDirectoryService;

import java.util.Hashtable;

public class CertDirectoryServiceProvider
  extends BaseSecurityServiceProvider
{
  private Hashtable ldapConnectionPool = new Hashtable();
  private static CACertDirectoryService caOperations = null;
  private ServiceBroker serviceBroker;

  public CertDirectoryServiceProvider(ServiceBroker sb, String community) {
    super(sb, community);

    serviceBroker = sb;
  }

  ///////////////////////////////////////
  // BEGIN ServiceProvider implementation

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
    Service theService = null;
    if (sb == null) {
      throw new IllegalArgumentException("Service Broker is null");
    }
    if (requestor == null) {
      log.error("Requestor is null");
      return null;
    }
    if (serviceClass == null) {
      log.error("Service class is null");
      return null;
    }

    if (serviceClass.equals(CertDirectoryServiceClient.class)) {
      if (!(requestor instanceof CertDirectoryServiceRequestor)) {
        log.error("Unsupported requestor type:" + requestor.getClass().getName());
        return null;
      }
      CertDirectoryServiceRequestor certRequestor = (CertDirectoryServiceRequestor) requestor;
      theService = getCertDirectoryServiceClientInstance(certRequestor, sb);
    }
    else if (serviceClass.equals(CertDirectoryServiceCA.class)) {
      if (!(requestor instanceof CertDirectoryServiceRequestor)) {
        log.error("Unsupported requestor type:" + requestor.getClass().getName());
        return null;
      }
      CertDirectoryServiceRequestor certRequestor = (CertDirectoryServiceRequestor) requestor;
      theService = getCertDirectoryServiceCAInstance(certRequestor, sb);
    }
    else if (serviceClass.equals(CACertDirectoryService.class)) {
      if (caOperations == null) {
        caOperations = new CACertDirectoryServiceImpl(serviceBroker);
      }
      theService = caOperations;
    }
    else {
      log.error("Unsupported service:" + serviceClass.getName());
    }
    if (theService == null) {
      log.warn("Unable to retrieve " + serviceClass.getName() + " service");
    }
    return theService;
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

  ///////////////////////////////////////
  // END ServiceProvider implementation

  private CertDirectoryServiceClient getCertDirectoryServiceClientInstance(CertDirectoryServiceRequestor requestor,
									   ServiceBroker theBroker)
  {
    CertDirectoryServiceClient ldapClient = null;
    String serverUrl = requestor.getCertDirectoryUrl();

    switch (requestor.getCertDirectoryType()) {
    case TrustedCaPolicy.COUGAAR_OPENLDAP:
      synchronized (ldapConnectionPool) {
	ldapClient = (CertDirectoryServiceClient) ldapConnectionPool.get(serverUrl);

	if (ldapClient == null) {
	  try {
	    ldapClient = new OpenLdapCertDirectoryServiceImpl(requestor, theBroker);
	  }
	  catch (javax.naming.NamingException e) {
	    log.warn("Unable to get LDAP directory service for URL:" + serverUrl + ". Reason:" + e);
	    return null;
	  }
	  // Add context to connection pool
	  ldapConnectionPool.put(serverUrl, ldapClient);
	}
	else if (!(ldapClient instanceof OpenLdapCertDirectoryServiceImpl)) {
	  log.error("Client Certificate directory service of wrong class ("
		    + ldapClient.getClass().getName() +
		    ") already registered for " + serverUrl);
	  ldapClient = null;
	}
      }
      break;

    case TrustedCaPolicy.NETTOOLS:
      synchronized (ldapConnectionPool) {
	ldapClient = (CertDirectoryServiceClient) ldapConnectionPool.get(serverUrl);
	if (ldapClient == null) {
	  try {
	    ldapClient = new NetToolsCertDirectoryService(requestor, theBroker);
	  }
	  catch (javax.naming.NamingException e) {
	    log.warn("Unable to get Nettools directory service for URL: " + serverUrl + ". Reason:" + e);
	    return null;
	  }

	  // Add context to connection pool
	  ldapConnectionPool.put(serverUrl, ldapClient);
	}
	else if (!(ldapClient instanceof NetToolsCertDirectoryService)) {
	  log.error("Client Certificate directory service of wrong class ("
		    + ldapClient.getClass().getName() +
		    ") already registered for " + serverUrl);
	  ldapClient = null;
	}
      }
      break;

      /*
    case 0:
      ldapClient = new CertificateDirectoryHandler(requestor, theBroker);
      break;
      */

    default:
      if (log.isWarnEnabled()) {
	log.warn("Client: Unknown directory service type: " + requestor.getCertDirectoryType(), new Throwable());
      }
    }
    return ldapClient;
  }

  public CertDirectoryServiceCA getCertDirectoryServiceCAInstance(CertDirectoryServiceRequestor requestor,
								  ServiceBroker theBroker)
  {
    CertDirectoryServiceCA caService = null;
    String serverUrl = requestor.getCertDirectoryUrl();

    switch (requestor.getCertDirectoryType()) {
    case TrustedCaPolicy.COUGAAR_OPENLDAP:
      synchronized (ldapConnectionPool) {
	caService = (CertDirectoryServiceCA)ldapConnectionPool.get(serverUrl);

	if (caService == null) {
	  try {
	    caService = new OpenLdapCertDirectoryServiceImpl(requestor, theBroker);
	  }
	  catch (javax.naming.NamingException e) {
	    log.warn("CA - Unable to get LDAP directory service for URL: " + serverUrl + ". Reason:" + e);
	    return null;
	  }

	  // Add context to connection pool
	  ldapConnectionPool.put(serverUrl, caService);
	}
	else if (!(caService instanceof OpenLdapCertDirectoryServiceImpl)) {
	  log.error("CA Certificate directory service of wrong class ("
		    + caService.getClass().getName() +
		    ") already registered for " + serverUrl);
	  caService = null;
	}
      }
      break;

    default:
      // Net Tools does not support CA functions programmatically.
      if (log.isWarnEnabled()) {
	log.warn("CA: Unknown directory service type: " + requestor.getCertDirectoryType());
      }
    }
    return caService;
  }
}








