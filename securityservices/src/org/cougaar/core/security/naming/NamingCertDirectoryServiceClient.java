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

public class NamingCertDirectoryServiceClient {
  LoggingService log;
  ServiceBroker sb;
  WhitePagesService whitePagesService;
  KeyRingService keyRingService;
  //Hashtable certCache = new Hashtable();

  /**
   * This class only handles updating cert directly to naming
   */
  public NamingCertDirectoryServiceClient(ServiceBroker serviceBroker) {
    sb = serviceBroker;

    log = (LoggingService)
      sb.getService(this,
			       LoggingService.class,
			       null);

    whitePagesService = (WhitePagesService)
      sb.getService(this, WhitePagesService.class, null);

    keyRingService = (KeyRingService)
      sb.getService(this, KeyRingService.class, null);

    // to poll naming if naming service does not handle updating objects
    /*
    NamingMonitorThread t = new NamingMonitorThread();
    t.start();
    */
  }

  public boolean updateCert(X500Name dname) throws Exception {
    String cname = dname.getCommonName();
    List l = keyRingService.getValidCertificates(dname);
    if (l == null || l.size() == 0) {
      if (log.isDebugEnabled()) {
        log.debug("No valid certificate to update naming entry: " + dname);
      }
      return false;
    }

    CertificateStatus cs = (CertificateStatus)l.get(0);
    NamingCertEntry entry = new NamingCertEntry();
    CertificateEntry certEntry = new CertificateEntry(cs.getCertificate(),
        CertificateUtility.getUniqueIdentifier(cs.getCertificate()),
        // of course the cert is trusted by local node, otherwise not valid
        CertificateRevocationStatus.VALID,
        cs.getCertificateType());
    certEntry.setCertificateChain(cs.getCertificateChain());
    entry.addEntry(dname, certEntry);
    updateCert(cname, entry);
    return true;
  }

  public void updateNS(X500Name dname) {
  /*
    synchronized (this) {
      if (!connected) {
        certCache.put(dname.getName(), dname);
      }
      else {
      */
        try {
          updateCert(dname);
        } catch (Exception ex) {
          if (log.isWarnEnabled()) {
            log.warn("Unable to update naming with naming started. " + ex);
          }
        }
      //}
    //}
  }

  /*
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
  public void updateCert(String cname, Cert entry) throws Exception {
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
  }

}