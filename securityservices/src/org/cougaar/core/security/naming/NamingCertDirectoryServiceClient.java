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

    // to poll naming if naming service does not handle updating objects
    /*
    NamingMonitorThread t = new NamingMonitorThread();
    t.start();
    */
  }

  public boolean updateCert(CertificateEntry certEntry) throws Exception {
    X509Certificate c = (X509Certificate)certEntry.getCertificate();
    String dname = c.getSubjectDN().getName();
    String cname = new X500Name(dname).getCommonName();

    NamingCertEntry entry = null;

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

        synchronized (certCache) {
          for (Iterator it = certCache.values().iterator(); it.hasNext(); ) {
            CertificateEntry cachedEntry = (CertificateEntry)it.next();
            updateCert(cachedEntry);
          }
        }
        certCache.clear();
      }
    }

    if (whitePagesService == null) {
      whitePagesService = (WhitePagesService)
        sb.getService(this, WhitePagesService.class, null);
    }
    if (whitePagesService == null) {
      log.warn("Cannot get white page service.");
      return false;
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
    entry.addEntry(dname, certEntry);
    updateCert(cname, entry);

    return true;
  }

  /*
  public void updateNS(X500Name dname) {
    synchronized (this) {
      if (!connected) {
        certCache.put(dname.getName(), dname);
      }
      else {
        try {
          updateCert(dname);
        } catch (Exception ex) {
          if (log.isWarnEnabled()) {
            log.warn("Unable to update naming with naming started. ", ex);
          }
        }
      }
    }
  }

  boolean connected = false;
  class NamingMonitorThread extends Thread {

    public void run() {
      // try to update the first cert until successful
      while (true) {
        synchronized (NamingCertDirectoryServiceClient.this) {
          for (Iterator it = certCache.entrySet().iterator(); it.hasNext(); ) {
            X500Name dname = (X500Name)it.next();
            try {
              if (!updateCert(dname)) {
                break;
              }
              connected = true;

            } catch (Exception ex) {
              if (log.isDebugEnabled()) {
                log.debug("Unable to update naming: " + ex);
              }
            }
          }
        }

        try {
          Thread.sleep(1000);
        }
        catch(InterruptedException interruptedexp) {
          interruptedexp.printStackTrace();
        }
      }
    }
  }
  */

  // for now when an identity starts it will overwrite the original
  // naming service entry (the entry it updated at last start)
  private void updateCert(String cname, Cert entry) throws Exception {
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

}