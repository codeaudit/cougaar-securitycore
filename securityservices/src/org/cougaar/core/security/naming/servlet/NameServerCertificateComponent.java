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


package org.cougaar.core.security.naming.servlet;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.crypto.CertValidityListener;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.services.crypto.CertValidityService;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.security.util.ServletRequestUtil;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import org.cougaar.core.service.wp.AddressEntry;
import org.cougaar.core.wp.resolver.ConfigReader;

public class NameServerCertificateComponent extends ComponentPlugin {
  private static Logger log;
  private CertificateCacheService cacheservice;
  private CertValidityService _validityService;

  private boolean _isNameServer = false;
  private Hashtable _nameservers = new Hashtable();
  private String _path;

  private static Hashtable _certCache = new Hashtable();
  private static Hashtable _pendingCache = new Hashtable();
  private static Hashtable _submitList = new Hashtable();
  private long _period = 10000;

  private CryptoClientPolicy cryptoClientPolicy;

  static {
    log = LoggerFactory.getInstance().
      createLogger(NameServerCertificateComponent.class);
  }

  public static Object getNameServerCert(String nameserver) {
    return _certCache.get(nameserver);
  }

  public static void addToNameCertCache(NameServerCertificate nameCert) {
    String nameserver = nameCert.getServer();
    if (log.isDebugEnabled()) {
      log.debug("Adding certs for " + nameserver);
    }
    _certCache.put(nameserver, nameCert);
    _submitList.put(nameserver, nameserver);
  }

  public static Hashtable getPendingList() {
    return _pendingCache;
  }

  public void load() {
    super.load();
    cacheservice = (CertificateCacheService)
        getServiceBroker().getService(this,
                             CertificateCacheService.class, null);

    _validityService = (CertValidityService)
          AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
              return getServiceBroker().getService(this,
                                   CertValidityService.class, null);
            }
          });

    if (_validityService == null) {
      throw new RuntimeException("Fail to obtain CertValidityService");
    }
  
    readNameServerConfig();

    if (log.isDebugEnabled()) {
      log.debug("isNameServer: " + _isNameServer);
    }

    // if so notify CA when naming certificate becomes available
    if (_isNameServer) {
      for (Enumeration en = _nameservers.keys(); en.hasMoreElements(); ) {
        String agent = (String)en.nextElement();
        if (!getNamingCert(agent)) {
          if (log.isDebugEnabled()) {
            log.debug("Need to wait for cert " + agent + " generation");
          }
          addValidityListener(agent);
        }
      }
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

  private void readNameServerConfig() {
    // regardless of the naming server configs, we get the entries that
    // are parsed by ConfigReader.
    Iterator i = ConfigReader.listEntries().iterator();
    // iterator through the list of naming server entries
    while(i.hasNext()) {
      AddressEntry entry = (AddressEntry)i.next();
      
      if (log.isDebugEnabled()) {
          log.debug("NamingServer AddressEntry: " + entry);
      }
      
      // we should match all local WP binds that aren't of type alias.
      // this could be -HTTP, -HTTPS, -RMI_REG
      if(!entry.getType().equals("alias")) {
        
        String host = entry.getURI().getHost();
        String agent = entry.getName(); 
        if (log.isDebugEnabled()) {
          log.debug("Name server is " + agent + ":" + host + " Localhost:"
          + NodeInfo.getHostName());
        }
        //if (NodeInfo.getNodeName().equals(agent)) {
        if (getAgentIdentifier().toString().equals(agent)) {
          _isNameServer = true; 
          _nameservers.put(agent, 
            new NameServerCertificate(agent, null));
        }
        else {
          if (agent == null) {
            if (log.isErrorEnabled()) {
              log.error("Cannot add null to pending cache", new Throwable());
            }
          }
          else {
            _pendingCache.put(agent, agent);
          }
        }
      }
    }
  }
  
  private void addValidityListener(final String agent) {
    _validityService.addAvailabilityListener(new CertValidityListener() {
      public String getName() {
        return agent;
      }
 
      public void invalidate(String cname) {}

      public void updateCertificate() {
        if (log.isDebugEnabled()) {
          log.debug("node cert generated, next update CA naming server cert");
        }
        if (!getNamingCert(agent)) {
          log.info("Fail to update node certificate for " + agent);
        }
        else {
          _submitList.put(agent, agent);
        }
      }
    });
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

  private boolean getNamingCert(String agent) {
    NameServerCertificate nameCert = (NameServerCertificate)
      _nameservers.get(agent);
    if (nameCert == null) {
      log.warn("no entry found for " + agent);
      return false; 
    }

    KeyRingService keyRing = (KeyRingService)
      getServiceBroker().getService(this,
                             KeyRingService.class, null);
    List l = keyRing.findCert(agent);
    getServiceBroker().releaseService(this, KeyRingService.class, keyRing);
    if (l != null && l.size() != 0) {
      CertificateStatus cs = (CertificateStatus)l.get(0);
      X509Certificate [] certs = keyRing.buildCertificateChain(cs.getCertificate());
      
      _certCache.put(agent, new NameServerCertificate(agent, certs));
      if (log.isDebugEnabled()) {
        log.debug("registering name server cert for " + agent + " : " +
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
            for (Iterator it = _submitList.values().iterator(); it.hasNext(); ) {
              String nameserver = (String)it.next();

              try {
                if (log.isDebugEnabled()) {
                  log.debug("submitting " + nameserver + " cert to " + certURL);
                }
                new ServletRequestUtil().sendRequest(certURL,
                    _certCache.get(nameserver), _period);

                // as long as one as submitted upward, the cert will propagate to
                // the top so that everyone will find it
                
                  _submitList.remove(nameserver);
                break;

              } catch (Exception ex) {
                if (ex instanceof IOException) {
                  if (log.isDebugEnabled()) {
                    log.debug("Waiting to " + nameserver + " cert to " + certURL);
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
          Thread.sleep(_period);
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
          Thread.sleep(_period);
        } catch (Exception ex) {}
      }
    }
  }

  void requestCert(String certURL) {
    synchronized (_pendingCache) {
      if (_pendingCache.size() != 0) {
        try {
          String [] names = new String[_pendingCache.size()];
          _pendingCache.values().toArray(names);
          ObjectInputStream ois = new ObjectInputStream(
            new ServletRequestUtil().sendRequest(certURL, names, _period));
          NameServerCertificate [] certs = (NameServerCertificate [])ois.readObject();
          ois.close();

          if (log.isDebugEnabled()) {
            log.debug("Received reply from " + certURL + " for name server cert");
          }

          for (int i = 0; i < certs.length; i++) {
            if (certs[i] != null) {
              if (log.isDebugEnabled()) {
                log.debug("Got cert for " + certs[i]);
              }

              // the returning array should be listed at the same sequence as 
              // the sending array
              _pendingCache.remove(certs[i].getServer());
              _certCache.put(certs[i].getServer(), certs[i]);
              // this is not SSL certificate but we borrow it
              for (int j = 0; j < certs[i].getCertChain().length; j++) {
                cacheservice.addSSLCertificateToCache(certs[i].getCertChain()[j]);
              }
            }
          }
        } catch (Exception ex) {
          if (ex instanceof IOException) {
            if (log.isDebugEnabled()) {
              log.debug("Waiting to get naming cert from " + certURL, ex);
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
