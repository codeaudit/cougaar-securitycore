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
