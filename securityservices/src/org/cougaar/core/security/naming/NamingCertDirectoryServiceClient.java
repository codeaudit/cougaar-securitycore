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

import java.security.cert.*;
import java.security.*;
import sun.security.x509.*;
import java.net.*;
import java.util.*;

import org.cougaar.core.service.wp.*;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceAvailableEvent;

import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.crypto.ldap.*;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.util.*;

public class NamingCertDirectoryServiceClient {
  LoggingService log;
  ServiceBroker sb;
  WhitePagesService whitePagesService;
  Hashtable certCache = new Hashtable();
  boolean nodeupdated = false;

  /**
   * This class only handles updating cert directly to naming
   */
  public NamingCertDirectoryServiceClient(ServiceBroker serviceBroker) {
    sb = serviceBroker;

    log = (LoggingService)
      sb.getService(this,
                    LoggingService.class,
                    null);

    if (log.isDebugEnabled()) {
      log.debug("Adding service listner for naming service :");
    }
    sb.addServiceListener(new NamingServiceAvailableListener());
  }

  public boolean updateCert(CertificateEntry certEntry) throws Exception {
    X509Certificate c = (X509Certificate)certEntry.getCertificate();
    String dname = c.getSubjectDN().getName();
    String cname = new X500Name(dname).getCommonName();

    // node cert need to be there before anything else can be published

    if (!nodeupdated) {
      if (!cname.equals(NodeInfo.getNodeName())) {
        if (log.isDebugEnabled()) {
          log.debug("storing " + dname
                    + " before node cert registers to naming");
        }

        certCache.put(dname, certEntry);
        return false;
      }
      else {
        nodeupdated = true;

        if (log.isDebugEnabled()) {
          log.debug("updating other cert entries now node cert is created.");
        }
        updateCertEntryFromCache();
      }
    }
    if (whitePagesService == null) {
      if (log.isDebugEnabled()) {
        log.debug("Naming service is not yet available, storing to cache.");
      }
      certCache.put(dname, certEntry);
      return false;
    }

    // naming bug: naming service is enabled before naming thread is created
    // so there is a problem updating naming even though naming service is available
    // need to wait until we successfully updated naming for an entry (should happen
    // after agents registers
    if (updateCertEntry(certEntry)) {
      if (!certCache.isEmpty()) {
        updateCertEntryFromCache();
      }
      return true;
    }
    return false;
  }

  private void setNamingService() {
    whitePagesService = (WhitePagesService)
      sb.getService(this, WhitePagesService.class, null);

    updateCertEntryFromCache();
  }

  private void updateCertEntryFromCache() {
    if (!nodeupdated) {
      if (log.isDebugEnabled()) {
        log.debug("update cert from cache: need to wait until node is enabled");
      }
      return;
    }
    if (whitePagesService == null) {
      if (log.isDebugEnabled()) {
        log.debug("update cert from cache: need to wait until white pages is available");
      }
      return;
    }

    synchronized (certCache) {
      for (Iterator it = certCache.values().iterator(); it.hasNext(); ) {
        CertificateEntry cachedEntry = (CertificateEntry)it.next();
        if (log.isDebugEnabled()) {
          log.debug("updating " + cachedEntry.getCertificate().getSubjectDN()
                    + " after node cert updated in naming.");
        }
        try {
          updateCertEntry(cachedEntry);
        } catch (Exception ex) {
          //log.warn("Failed to update naming: ", ex);
          return;
        }
      }
    }
    certCache.clear();
  }

  private boolean updateCertEntry(CertificateEntry certEntry) throws Exception {
    X509Certificate c = (X509Certificate)certEntry.getCertificate();
    String dname = c.getSubjectDN().getName();
    String cname = new X500Name(dname).getCommonName();
    NamingCertEntry entry = null;

    if (whitePagesService == null) {
      log.warn("Cannot get white page service.");
      throw new Exception("Naming service is not available yet.");
    }

    if (log.isDebugEnabled()) {
      log.debug("updating NS for " + dname);
    }

    AddressEntry ael = whitePagesService.get(cname,
                                             Application.getApplication("topology"), "cert");
    if (ael != null) {
      Cert cert = ael.getCert();
      if (cert instanceof NamingCertEntry) {
        entry = (NamingCertEntry)cert;
        if (log.isDebugEnabled()) {
          log.debug("Cert type found in naming, updating");
        }
      }
      else {
        if (log.isDebugEnabled()) {
          log.debug("Different Cert type in naming, replacing");
        }
      }
    }
    if (entry == null) {
      if (log.isDebugEnabled()) {
        log.debug("Creating new NamingCertEntry to update naming");
      }
      entry = new NamingCertEntry();
    }
    entry.addEntry(dname, certEntry, true);
    updateCert(cname, entry);

    return true;
  }

  // for now when an identity starts it will overwrite the original
  // naming service entry (the entry it updated at last start)
  public void updateCert(String cname, Cert entry) throws Exception {
    if(cname==null){
      log.error(" cname is NULL  in updateCert:");
    }
     if(entry==null) {
      log.error(" entry is NULL in updateCert:");
    }
    URI certURI =
      URI.create("cert://"+cname);
    AddressEntry certEntry =
      new AddressEntry(
        cname,
        Application.getApplication("topology"),
        certURI,
        entry,
        Long.MAX_VALUE);
    whitePagesService.rebind(certEntry);

    if (log.isDebugEnabled()) {
      log.debug("Successfully updated naming: " + cname);
    }
  }

  private class NamingServiceAvailableListener implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      if(org.cougaar.core.service.wp.WhitePagesService.class.isAssignableFrom(sc)) {
	log.debug("Naming Service is now available");
        setNamingService();
      }
    }
  }


}
