/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

import java.io.*;
import java.util.*;
import java.security.cert.*;
import java.security.*;
import sun.security.x509.*;
import java.net.*;

import org.cougaar.core.service.wp.*;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.services.crypto.*;

public class CertificateSearchServiceImpl
  implements CertificateSearchService
{
  private LoggingService log;
  private ServiceBroker sb;
  private WhitePagesService whitePagesService;
  private KeyRingService keyRingService;
  private CertDirectoryServiceFactory fac;

  public CertificateSearchServiceImpl(ServiceBroker serviceBroker,
                                      CertDirectoryServiceFactory factory) {
    sb = serviceBroker;
    fac = factory;

    log = (LoggingService)
      sb.getService(this, LoggingService.class,
                    null);
    
  }

  public List findDNFromNS(String cname) {
    if (log.isDebugEnabled()) {
      log.debug("findDNFromNS: " + cname);
    }
    ArrayList l = new ArrayList();
    if (whitePagesService == null) {
      whitePagesService = (WhitePagesService)
        sb.getService(this, WhitePagesService.class, null);
    }
    if (whitePagesService == null) {
      return l;
    }
    try {
      AddressEntry ael = whitePagesService.get(cname,
					       WhitePagesUtil.WP_CERTIFICATE_TYPE);
      if (ael == null) {
        if (log.isDebugEnabled()) {
          log.debug("Unable to find cert entry in naming: " + cname);
        }
        return l;
      }
      Cert cert = ael.getCert();
      if (cert == Cert.PROXY) {
        // go to contact the agent with attribute cert provider
      }
      else if (cert instanceof NamingCertEntry) {
        Iterator it = ((NamingCertEntry)cert).getDNList().iterator();
        for (; it.hasNext(); ) {
          l.add(new X500Name((String)it.next()));
        }
        if (log.isDebugEnabled()) {
          log.debug("Retrieved cert entry from naming for " + cname + " size: " + l.size());
        }
      }
      else if (cert instanceof IndirectCertEntry) {
        Iterator it = ((IndirectCertEntry)cert).getDNList().iterator();
        for (; it.hasNext(); ) {
          l.add(new X500Name((String)it.next()));
        }
      }
      else {
        // every name in naming should have a certificate
        if (cert == Cert.NULL) {
          if (log.isWarnEnabled()) {
            log.warn(cname + " is registered but has no cert.");
          }
        }
        else {
          if (log.isWarnEnabled()) {
            log.warn(cname + " has unknown cert type in naming.");
          }
        }
        // should this raise an alert?
      }
    } catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("Failed to request from naming: ", ex);
      }
    }
    return l;
  }

  /**
   * returns a list of certificate chains, chain has been validated
   * CertificateCache will be updated with the certs
   * Finds any certificate, including invalid ones
   * It is up to the caller to choose what it needs
   */
  public List findCert(X500Name dname) {
    if (log.isDebugEnabled()) {
      log.debug("findCert: " + dname.getName());
    }
    if (keyRingService == null) {
      keyRingService=(KeyRingService)
        sb.getService(this,
                      KeyRingService.class,
                      null);
    }


    ArrayList l = new ArrayList();
    if (whitePagesService == null) {
      whitePagesService = (WhitePagesService)
        sb.getService(this, WhitePagesService.class, null);
    }
    if (whitePagesService == null) {
      return l;
    }
    String dnameString = dname.getName();
    try {
      String cname = dname.getCommonName();
      CertificateStatus cs = null;
      AddressEntry ael = whitePagesService.get(cname,
					       WhitePagesUtil.WP_CERTIFICATE_TYPE);
      if (ael == null) {
        if (log.isDebugEnabled()) {
          log.debug("Unable to find cert entry in naming: " + cname);
        }
        return l;
      }

      Cert cert = ael.getCert();
      if (cert == Cert.PROXY) {
        // go to contact the agent with attribute cert provider
      }
      else if (cert instanceof NamingCertEntry) {
        NamingCertEntry nce = (NamingCertEntry)cert;
        for (Iterator it = nce.getEntries().iterator(); it.hasNext(); ) {
          CertificateEntry entry = (CertificateEntry)it.next();
          X509Certificate c = entry.getCertificate();
          // NamingCertEntry includes all certs for a common name
          if (!c.getSubjectDN().getName().equals(dnameString))
            continue;

          l.add(entry);
        }
      }
      else if (cert instanceof IndirectCertEntry) {
        IndirectCertEntry indirectCert = (IndirectCertEntry)cert;

        for (Iterator it = indirectCert.getQueries().iterator(); it.hasNext(); ) {
          String query = (String)it.next();
          URI reqUri = null;
          try {
            reqUri = new URI(query);
          } catch (Exception ex) {
            if (log.isWarnEnabled()) {
              log.warn(cname + " has unrecognized query: " + query);
            }
            return l;
          }

          CertDirectoryService lookupService = getCertDirectoryService(
            reqUri.getScheme());
          if (lookupService == null) {
            throw new Exception("No lookup service available for: " + reqUri.getScheme());
          }
          // this does not build the chain, only grab the certs from ldap
          List certList = lookupService.findCert(dname, reqUri);
          /*
            for (Iterator it = certList.iterator(); it.hasNext(); ) {
            X509Certificate [] certChain = (X509Certificate [])it.next();
            if (certChain.length == 0) {
            continue;
            }
            // is chain included?
            if (certChain.length == 1) {
            // use KeyRingService to build chain
            try {
            cs = keyRingService.buildCertificateChain(c, reqUri);
            } catch (CertificateException cex) {
            continue;
            }
            }
            else {
            cs = keyRingService.checkCertificateTrust(certChain);
            }

            l.add(cs);
            }
          */
          l.addAll(certList);
        }
      }
      else {
        // every name in naming should have a certificate
        if (cert == Cert.NULL) {
          if (log.isWarnEnabled()) {
            log.warn(cname + " is registered but has no cert.");
          }
        }
        else {
          if (log.isWarnEnabled()) {
            log.warn(cname + " has unknown cert type in naming.");
          }
        }
        // should this raise an alert?
      }
      return l;
    } catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("Failed to request from naming: ", ex);
      }
    }
    return l;
  }

  public CertDirectoryService getCertDirectoryService(String scheme) {
    return fac.getCertDirectoryService(scheme);
  }

}
