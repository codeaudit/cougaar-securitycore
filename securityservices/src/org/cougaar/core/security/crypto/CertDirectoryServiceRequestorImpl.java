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


package org.cougaar.core.security.crypto;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.service.LoggingService;

import sun.security.x509.X500Name;

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

  /**
   * Only url is needed, will match with existing ldap urls from CaPolicy
   */
  public CertDirectoryServiceRequestorImpl(String url, ServiceBroker sb) {
    String principal = null;
    String credential = null;
    int type = 0;

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

        // for now, default to the first LDAP credential we find
        // it should actually be searching for one that matches the URL
        TrustedCaPolicy tc = cryptoClientPolicy.getTrustedCaPolicy()[0];
	principal = tc.certDirectoryPrincipal;
	credential = tc.certDirectoryCredential;
        type = tc.certDirectoryType;
      }
      else {
        X500Name [] caDNs = configParser.getCaDNs();
	for (int i = 0; i < caDNs.length; i++) {
          X500Name dname = caDNs[i];
          String caDn = dname.getName();

	  CaPolicy caPolicy = configParser.getCaPolicy(caDn);
	  if (caPolicy == null) {
	    log.info("Unable to get CA policy");
            continue;
	  }
	  else {
	    principal = caPolicy.ldapPrincipal;
	    credential = caPolicy.ldapCredential;
            type = caPolicy.ldapType;
	  }
	}

        if (principal == null) {
          if (log.isDebugEnabled()) {
            log.debug("NO policy found for ldap URL " + url
              + ", using default credentials.");
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
