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

import java.net.URI;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.CertDirectoryService;
import org.cougaar.core.security.services.util.CertificateSearchService;
import org.cougaar.core.security.services.util.WhitePagesUtil;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.wp.AddressEntry;
import org.cougaar.core.service.wp.Callback;
import org.cougaar.core.service.wp.Cert;
import org.cougaar.core.service.wp.Request;
import org.cougaar.core.service.wp.Response;
import org.cougaar.core.service.wp.WhitePagesService;

import sun.security.x509.X500Name;

public class CertificateSearchServiceImpl
  implements CertificateSearchService
{
  private LoggingService log;
  private ServiceBroker sb;
  private WhitePagesService whitePagesService;
  private KeyRingService keyRingService;
  private CertDirectoryServiceFactory fac;

  private int dn_memory_count = 0;
  private int find_memory_count = 0;
  private int _detectMemory = 0;

  public CertificateSearchServiceImpl(ServiceBroker serviceBroker,
                                      CertDirectoryServiceFactory factory) {
    sb = serviceBroker;
    fac = factory;

    log = (LoggingService)
      sb.getService(this, LoggingService.class,
                    null);

    String detect = System.getProperty("org.cougaar.core.security.repeat_wp_count", null);
    try {
      _detectMemory = Integer.parseInt(detect);
    } catch (Exception ex) {}
    if (log.isDebugEnabled()) {
      log.debug("repeat " + _detectMemory + " times for every wp request");
    }

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
      AddressEntry ael = fetchCertEntry(cname, null);
      if (_detectMemory != 0) {
        for (int i = 0; i < _detectMemory; i++) {
          String testname = cname + i;
          fetchCertEntry(testname, null);
        }
        dn_memory_count++;

        if (log.isDebugEnabled()) {
          int total = dn_memory_count + find_memory_count;
          if (total % 100 == 0) {
            log.debug("memory detection: " + dn_memory_count + " times check dn " + find_memory_count + " times check certificate");
          }
        }
      }      
      //AddressEntry ael = whitePagesService.refresh(cname, WhitePagesUtil.WP_CERTIFICATE_TYPE,1);
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
    return findCert(dname, null);
  }

  public List findCert(final X500Name dname, final SearchCallback scb) {
    if (log.isDebugEnabled()) {
      log.debug("findCert: " + dname.getName());
    }
    if (keyRingService == null) {
      keyRingService=(KeyRingService)
        AccessController.doPrivileged(new PrivilegedAction() 
          {
            public Object run()
            {
              return sb.getService(this,
                                   KeyRingService.class,
                                   null);
            }
          });
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
      final String cname = dname.getCommonName();
      //AddressEntry ael = whitePagesService.get(cname,WhitePagesUtil.WP_CERTIFICATE_TYPE,1);
      
      Callback callback = null;
      if (scb != null) {
    /** Callback to handle White page response.
     */
      callback = new Callback() {
      /** Handle a WhitePagesService response. */
      public void execute(Response res) {
        if (res.isSuccess()) {
          if (log.isDebugEnabled()) {
            log.debug("Got response back in callback for " + cname);
          }
          AddressEntry ael = ((Response.Get)res).getAddressEntry();
          //wpCache.put(cname, ((Response.Get)res).getAddressEntry());
            scb.searchCallback(dname.getName(), 
              processFindResponse(cname, dname, ael));
            
        }
        else {
          if (log.isDebugEnabled()) {
            log.debug("Got no response back for " + cname + " res: " + res);
          }
        }
      }
    };

      }
      AddressEntry ael = fetchCertEntry(cname, callback);
      if (_detectMemory != 0) {
        for (int i = 0; i < _detectMemory; i++) {
          String testname = cname + i;
          fetchCertEntry(testname, null);
        }
        find_memory_count++;

        if (log.isDebugEnabled()) {
          int total = dn_memory_count + find_memory_count;
          if (total % 100 == 0) {
            log.debug("memory detection: " + dn_memory_count + " times check dn " + find_memory_count + " times check certificate");
          }
        }
      }      

      if (scb == null) {
        return processFindResponse(cname, dname, ael);
      }
    } catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("Failed to request from naming: ", ex);
      }
    }
    return l;
  }

  private List processFindResponse(String cname, X500Name dname, AddressEntry ael) {
      List l = new ArrayList();
      if (ael == null) {
        if (log.isDebugEnabled()) {
          log.debug("Unable to find cert entry in naming: " + cname);
        }

        return l;
      }

      String dnameString = dname.getName();
      Cert cert = ael.getCert();
      if (cert == Cert.PROXY) {
        // go to contact the agent with attribute cert provider
      }
      else if (cert instanceof NamingCertEntry) {
        NamingCertEntry nce = (NamingCertEntry)cert;

        if (log.isDebugEnabled()) {
          log.debug("Got entry : " + nce.toString() + " with hash code " + nce.hashCode());
        }

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
/*
          if (lookupService == null) {
            throw new Exception("No lookup service available for: " + reqUri.getScheme());
          }
*/
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
  }

  public CertDirectoryService getCertDirectoryService(String scheme) {
    return fac.getCertDirectoryService(scheme);
  }

  private AddressEntry fetchCertEntry(final String cname, Callback callback)
    throws Exception
  {
    // look up cache
    /*
    Response r = whitePagesService.submit(
      new Request.Get(Request.CACHE_ONLY,
        cname, WhitePagesUtil.WP_CERTIFICATE_TYPE));
    AddressEntry ael = ((Response.Get)r).getAddressEntry();
    if (ael != null) {
      if (log.isDebugEnabled()) {
        log.debug("Found entry " + cname);
      }
      return ael;
    }
    */

    if (callback != null) {
      Response r = whitePagesService.submit(
        new Request.Get(Request.NONE,
          cname, WhitePagesUtil.WP_CERTIFICATE_TYPE), callback);
      return null;
    }

    Response r = whitePagesService.submit(
      new Request.Get(Request.NONE,
        cname, WhitePagesUtil.WP_CERTIFICATE_TYPE)/*, callback*/);
    if (r.waitForIsAvailable(1)) {
      if (r.isSuccess()) {
        if (log.isDebugEnabled()) {
          log.debug("Found entry " + cname);
        }
        return ((Response.Get)r).getAddressEntry();
      }
      else if (r.isTimeout()) {
      }
      else {
        throw r.getException();
      }
    }

    //return (AddressEntry)wpCache.get(cname);
    return null;
  }

  //Hashtable wpCache = new Hashtable();

}
