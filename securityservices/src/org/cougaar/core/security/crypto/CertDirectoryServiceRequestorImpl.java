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

package org.cougaar.core.security.crypto;

// Cougaar core infrastructure
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.CaPolicy;

public class CertDirectoryServiceRequestorImpl
  implements CertDirectoryServiceRequestor
{
  private String ldapUrl;
  private int ldapType;
  private String ldapPrincipal;
  private String ldapCredential;
  private LoggingService log;

  public CertDirectoryServiceRequestorImpl(String url, int type, String principal, String credential,
					   ServiceBroker sb) {
    init(url, type, principal, credential, sb);
  }

  public CertDirectoryServiceRequestorImpl(String url, int type, ServiceBroker sb, String caDn) {
    String principal = null;
    String credential = null;

    if (log == null) {
      log = (LoggingService) sb.getService(this, LoggingService.class, null);
    }
    log.debug(" ldap url is :"+ url +"ldap type is :"+type);
    try {
      ConfigParserService configParser = (ConfigParserService)
        sb.getService(this, ConfigParserService.class, null);

      if (!configParser.isCertificateAuthority()) {
	SecurityPolicy[] sp = configParser.getSecurityPolicies(CryptoClientPolicy.class);
	CryptoClientPolicy cryptoClientPolicy = (CryptoClientPolicy) sp[0];
	principal = cryptoClientPolicy.getTrustedCaPolicy()[0].certDirectoryPrincipal;
	credential = cryptoClientPolicy.getTrustedCaPolicy()[0].certDirectoryCredential;
      }
      else {
	if (caDn != null) {
	  CaPolicy caPolicy = configParser.getCaPolicy(caDn);
	  if (caPolicy == null) {
	    log.info("Unable to get CA policy");
	  }
	  else {
	    principal = caPolicy.ldapPrincipal;
	    credential = caPolicy.ldapCredential;
	  }
	}
      }
    }
    catch (Exception e) {
      log.warn("Unable to get LDAP credentials:" + e);
    }
    init(url, type, principal, credential, sb);
  }

  /** Get the requested URL to the LDAP certificate directory service. */
  public String getCertDirectoryUrl() {
    return ldapUrl;
  }

  /** Get the type of the LDAP certificate directory service. */
  public int getCertDirectoryType() {
    return ldapType;
  }

  /** Get the principal used to establish to connection to LDAP */
  public String getCertDirectoryPrincipal() {
    return ldapPrincipal;
  }

  /** Get the credential used to establish to connection to LDAP */
  public String getCertDirectoryCredential() {
    return ldapCredential;
  }

  private void init(String url, int type, String principal, String credential, ServiceBroker sb) {
    ldapUrl = url;
    ldapType = type;
    ldapPrincipal = principal;
    ldapCredential = credential;

    if (log == null) {
      log = (LoggingService) sb.getService(this, LoggingService.class, null);
    }
    if (log.isDebugEnabled()) {
      log.debug("New LDAP connection:" + ldapUrl
		+ ". Principal: " + ldapPrincipal);
    }
  }

}
