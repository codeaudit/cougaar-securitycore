
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

package org.cougaar.core.security.naming.servlet;

import java.util.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.*;
import java.security.*;
import sun.security.x509.*;

import org.cougaar.core.component.*;
import org.cougaar.core.service.*;
import org.cougaar.core.plugin.ComponentPlugin;

import org.cougaar.core.security.util.*;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.certauthority.*;

public class NameServerCertificateComponent extends ComponentPlugin {
  private LoggingService log;
  private CertificateCacheService cacheservice;

  private boolean _isNameServer = false;
  private String _nameserver;
  private String _certName;
  private String _path;

  private static Hashtable _certCache = new Hashtable();
  private static List _pendingCache = new ArrayList();
  private static List _submitList = new ArrayList();
  private long _period = 10000;

  private CryptoClientPolicy cryptoClientPolicy;

  public static Object getNameServerCert(String nameserver) {
    return _certCache.get(nameserver);
  }

  public static void addToNameCertCache(String nameserver, X509Certificate [] certs) {
    _certCache.put(nameserver, certs);
    _submitList.add(nameserver);
  }

  public static List getPendingList() {
    return _pendingCache;
  }

  public void load() {
    super.load();

    log = (LoggingService)
        getServiceBroker().getService(this,
                             LoggingService.class, null);


    cacheservice = (CertificateCacheService)
        getServiceBroker().getService(this,
                             CertificateCacheService.class, null);

    _certName = NodeInfo.getNodeName();

    // check whether this is a name server
    String nameserver = System.getProperty("org.cougaar.name.server", null);
    if (nameserver == null) {
      log.warn("There is no property for name server, will NOT try to get name server certificate.");
      return;
    }

    _nameserver = nameserver.substring(0, nameserver.indexOf(':'));

    if (log.isDebugEnabled()) {
      log.debug("Name server is " + _nameserver + " localhost: " +
	NodeInfo.getHostName());
    }
    if (NodeInfo.getHostName().indexOf(_nameserver) != -1) {
      _isNameServer = true;
    }

      if (log.isDebugEnabled()) {
        log.debug("isNameServer: " + _isNameServer);
      }

    // if so notify CA when naming certificate becomes available
    if (_isNameServer) {
      if (!getNamingCert()) {
        if (log.isDebugEnabled()) {
          log.debug("Need to wait for node cert " + _certName + " generation");
        }

        CertValidityService validityService = (CertValidityService)
        AccessController.doPrivileged(new PrivilegedAction() {
          public Object run() {
            return getServiceBroker().getService(this,
                                 CertValidityService.class, null);
          }
        });

        if (validityService == null) {
          log.warn("Fail to obtain CertValidityService");
          return;
        }
        validityService.addValidityListener(new CertValidityListener() {
          public String getName() {
            return _certName;
          }

          public void updateCertificate() {
            if (log.isDebugEnabled()) {
              log.debug("node cert generated, next update CA naming server cert");
            }
            if (!getNamingCert()) {
              log.warn("Fail to update node certificate for " + _certName);
            }
            else {
              _submitList.add(_nameserver);
            }
          }
        });
      }
    }
    else {
      _pendingCache.add(_nameserver);
    }

    try {
      String prop = System.getProperty("org.cougaar.core.security.namecertpoll", "10");  // default to 10 secs
      _period = Long.parseLong(prop) * 1000; // in msecs
    }
    catch(NumberFormatException nfe) {
    }

    NameServerCertificateThread thread = new NameServerCertificateThread();
    thread.start();

  }

  private void getPolicy() {
    ConfigParserService parser = (ConfigParserService)
      getServiceBroker().getService(this,
                           ConfigParserService.class, null);
    SecurityPolicy[] sp =
      parser.getSecurityPolicies(CryptoClientPolicy.class);
    cryptoClientPolicy = (CryptoClientPolicy) sp[0];

    getServiceBroker().releaseService(this, ConfigParserService.class, parser);
    if (cryptoClientPolicy == null) {
      log.debug("no policy yet " + sp);
    }
  }

  private boolean getNamingCert() {
    KeyRingService keyRing = (KeyRingService)
      getServiceBroker().getService(this,
                             KeyRingService.class, null);
    List l = keyRing.findCert(_certName);
    getServiceBroker().releaseService(this, KeyRingService.class, keyRing);
    if (l != null && l.size() != 0) {
      CertificateStatus cs = (CertificateStatus)l.get(0);
      X509Certificate [] certs = keyRing.buildCertificateChain(cs.getCertificate());
      _certCache.put(_nameserver, certs);
      if (log.isDebugEnabled()) {
        log.debug("registering name server cert for " + _nameserver + " : " +
          cs.getCertificate());
      }
      return true;
    }
    return false;
  }

  public void setParameter(Object o) {
    List l=(List)o;
    _path=(String)l.get(0);
  }

  public void execute() {
  }

  public void unload() {
    super.unload();
    // FIXME release the rest!
  }

  protected void setupSubscriptions() {
  }


  class CertificateSubmitThread extends Thread {
    public void run() {
      while (true) {
        TrustedCaPolicy [] tc = cryptoClientPolicy.getIssuerPolicy();
        for (int i = 0; i < tc.length; i++) {
          String certURL = tc[i].caURL;
          certURL = certURL.substring(0, certURL.lastIndexOf('/'));
          certURL += "/" + _path;
          synchronized (_submitList) {
            for (Iterator it = _submitList.iterator(); it.hasNext(); ) {
              String nameserver = (String)it.next();

              try {
                if (log.isDebugEnabled()) {
                  log.debug("submiting name server cert to " + certURL);
                }
                new ServletRequestUtil().sendRequest(certURL,
                  new NameServerCertificate(nameserver,
                    (X509Certificate [])_certCache.get(nameserver)), _period);

                // as long as one as submitted upward, the cert will propagate to
                // the top so that everyone will find it
                _submitList.remove(nameserver);
                break;

              } catch (Exception ex) {
                if (ex instanceof IOException) {
                  if (log.isDebugEnabled()) {
                    log.debug("Waiting to submit naming cert to " + certURL);
                  }
                }
                else {
                  if (log.isWarnEnabled()) {
                    log.warn("Exception occurred. ", ex);
                  }
                  continue;
                }
              }
            }
          }
        }
        try {
          Thread.currentThread().sleep(_period);
        } catch (Exception ex) {}
      }
    }
  }

  class NameServerCertificateThread extends Thread {
    public void run() {
      while (true) {

        if (cryptoClientPolicy == null) {
          getPolicy();
          if (cryptoClientPolicy == null) {
            continue;
          }

          // no need to grab certificate or submit if is root CA
          // name cert will be submitted to it
          if (cryptoClientPolicy.isRootCA()) {
            break;
          }

          // if CA needs to propagate name server cert upward
          if (_isNameServer || cryptoClientPolicy.isCertificateAuthority()) {
            CertificateSubmitThread submit_t = new CertificateSubmitThread();
            submit_t.start();
          }
        }

        TrustedCaPolicy [] tc = cryptoClientPolicy.getIssuerPolicy();
        for (int i = 0; i < tc.length; i++) {
          String certURL = tc[i].caURL;
          certURL = certURL.substring(0, certURL.lastIndexOf('/'));
          certURL += "/" + _path;
          requestCert(certURL);
        }

        try {
          Thread.currentThread().sleep(_period);
        } catch (Exception ex) {}
      }
    }
  }

  void requestCert(String certURL) {
    synchronized (_pendingCache) {
      if (_pendingCache.size() != 0) {
        try {
          String [] names = new String[_pendingCache.size()];
          _pendingCache.toArray(names);

          ObjectInputStream ois = new ObjectInputStream(
            new ServletRequestUtil().sendRequest(certURL, names, _period));
          NameServerCertificate [] certs = (NameServerCertificate [])ois.readObject();
          ois.close();

          if (log.isDebugEnabled()) {
            log.debug("Received reply for name server cert");
          }

          for (int i = 0; i < certs.length; i++) {
            if (certs[i] != null) {
              if (log.isDebugEnabled()) {
                log.debug("Got cert for " + certs[i]);
              }
              _certCache.put(certs[i].nameserver, certs[i].certChain);
              _pendingCache.remove(names[i]);
              // this is not SSL certificate but we borrow it
              for (int j = 0; j < certs[i].certChain.length; j++) {
                cacheservice.addSSLCertificateToCache(certs[i].certChain[j]);
              }
            }
          }
        } catch (Exception ex) {
          if (ex instanceof IOException) {
            if (log.isDebugEnabled()) {
              log.debug("Waiting to get naming cert from " + certURL);
            }
          }
          else {
            if (log.isWarnEnabled()) {
              log.warn("Exception occurred. ", ex);
            }
            return;
          }
        }

      }

    }
  }


}
