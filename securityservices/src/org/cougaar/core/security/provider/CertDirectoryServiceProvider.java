/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
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








