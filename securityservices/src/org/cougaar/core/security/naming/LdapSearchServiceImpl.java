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


package org.cougaar.core.security.naming;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.CertDirectoryServiceRequestorImpl;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.ldap.LdapEntry;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;
import org.cougaar.core.security.services.util.CertDirectoryService;
import org.cougaar.core.service.LoggingService;

import java.net.URI;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import sun.security.x509.X500Name;

public class LdapSearchServiceImpl implements CertDirectoryService {
  private LoggingService log;
  private ServiceBroker sb;
  private Hashtable finderCache = new Hashtable();

  public LdapSearchServiceImpl(ServiceBroker serviceBroker) {
    sb = serviceBroker;

    log = (LoggingService)
      sb.getService(this,
			       LoggingService.class,
			       null);
  }

  public List findCert(X500Name dname, URI reqUri) {
    List l = new ArrayList();
    try {
      String url = reqUri.toString();
      CertDirectoryServiceClient certFinder = getServiceClient(url);
      String filter = CertificateUtility.parseDNforFilter(dname.getName());

      LdapEntry[] certs = null;
      if (certFinder != null) {
	certs = certFinder.searchWithFilter(filter);
	url = certFinder.getDirectoryServiceURL();
      }
      else {
	if (log.isWarnEnabled()) {
	  log.warn("Certificate finder is null. Unable to perform the search: " + filter)    ;
	}
      }
      if(certs==null) {
	if (log.isErrorEnabled()) {
	  log.error("LDAP search failed for: " + filter + " (" + url + ")");
	}
      }
      else {
	if (certs.length == 0) {
	  if (log.isWarnEnabled()) {
	    log.warn("Failed to lookup certificate for " + filter + " in LDAP:"
		     + url);
	  }
	}
      }
      for (int i = 0 ; i < certs.length ; i++) {
        l.add(certs);
      }

    } catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("findCert failed, reason: ", ex);
      }
    }
    return l;
  }

  private CertDirectoryServiceClient getServiceClient(String ldapUrl) {
    CertDirectoryServiceClient certificateFinder = (CertDirectoryServiceClient)
      finderCache.get(ldapUrl);
    if (certificateFinder == null) {
      CertDirectoryServiceRequestor cdsr =
        new CertDirectoryServiceRequestorImpl(ldapUrl, sb);
      certificateFinder = (CertDirectoryServiceClient)
        sb.getService(cdsr, CertDirectoryServiceClient.class, null);
      finderCache.put(ldapUrl, certificateFinder);
    }
    return certificateFinder;
  }


}
