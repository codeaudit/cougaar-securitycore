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

package org.cougaar.core.security.ssl;

import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.CertificateCache;
import org.cougaar.core.security.crypto.CertificateChainException;
import org.cougaar.core.security.crypto.CertificateRevokedException;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.service.LoggingService;

import sun.security.x509.X500Name;

public class TrustManager implements X509TrustManager {
  protected KeyRingService keyRing = null;
  //protected DirectoryKeyStore keystore = null;
  protected X509Certificate [] issuers = new X509Certificate [] {};
  private ServiceBroker serviceBroker;
  private LoggingService log;
  protected CertificateCacheService cacheservice = null;
  protected boolean skipTrustCheck = false;

  public TrustManager(KeyRingService krs, ServiceBroker sb, 
                      boolean skipTrustCheck) {
    this(krs, sb);
    this.skipTrustCheck = skipTrustCheck;
  }

  public TrustManager(KeyRingService krs, ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    keyRing = krs;
    //keystore = keyRing.getDirectoryKeyStore();

    updateKeystore();
    cacheservice=(CertificateCacheService)
      serviceBroker.getService(this,
                               CertificateCacheService.class,
                               null);
      if(cacheservice==null) {
        if (log.isDebugEnabled()){
          log.warn("Unable to get Certificate cache service in updateKeystore");
        }
      }
    cacheservice.addTrustListener(this);
  }

  public synchronized void updateKeystore() {
    CertificateCacheService cacheservice=(CertificateCacheService)
      serviceBroker.getService(this,
			       CertificateCacheService.class,
			       null);
    try {
      if(cacheservice==null) {
	if (log.isDebugEnabled()){
	  log.warn("Unable to get Certificate cache service in updateKeystore");
	 }
	return;
      }
	issuers = cacheservice.getTrustedIssuers();
    } catch (Exception ex) {
     	log.warn("Cannot update trusted keys: ", ex); 
    }
  }

  /**
   * Given the partial or complete certificate chain provided by the peer,
   * build a certificate path to a trusted root and return if it
   * can be validated and is trusted for client SSL authentication based
   * on the authentication type.
   */

  public void checkClientTrusted(X509Certificate[] chain, String authType)
    throws CertificateException
  {
    // check whether client is user or node
    if (chain == null || chain.length == 0) {
      log.warn("checkClientTrusted: No certificate present");
      throw new CertificateException("No certificate present");
    }

    if (log.isDebugEnabled()) {
      log.debug("checkClientTrusted: " + SSLDebug.getCertsDnNames(chain));
    }

    X509Certificate usrcert = chain[0];
    String clndn = usrcert.getSubjectDN().getName();
    String title = CertificateUtility.findAttribute(clndn, "t");
    // we allow users, agents, or nodes to access tomcat
    boolean accept = false;
    if (title != null) {
      if (title.equals(CertificateCache.CERT_TITLE_NODE)) {
        accept = true;
      }
      else if (title.equals(CertificateCache.CERT_TITLE_USER)
	  && this instanceof ServerTrustManager) {
        accept = true;
        // only allow skipping trust check for user
        // for HTTP link protocol the trust check will be done at the trust manager.
        // for normal user access to servlet the check will be done by DualAuthenticator
        if (skipTrustCheck) {
          if (log.isDebugEnabled()) {
            log.debug("Skipping certificate trust check: " + chain);
          }
          return;
        }

      }
      else if(title.equals(CertificateCache.CERT_TITLE_AGENT)
          && this instanceof ServerTrustManager) {
        accept = true;
      }
    }
    if (!accept) {
      String s = "Wrong type of client certificate. Title=" + title
        + " class=" + getClass().getName();
      log.warn(s);
      throw new CertificateException(s);
    }

    // check whether cert is valid, then build the chain
    try {
      checkChainTrust(chain);
      if (log.isDebugEnabled()) {
	log.debug("checkClientTrusted - Cert is trusted: "
		  + SSLDebug.getCertsDnNames(chain));
      }
    } catch (CertificateException e) {
      if (log.isDebugEnabled()) {
	log.debug("checkClientTrusted - Cert is NOT trusted: "
		  + SSLDebug.getCertsDnNames(chain) + " Reason: " + e);
      }
      String msgType = "ServerTrustManager";
      if (e instanceof CertificateRevokedException) {
        event("CertificateRevoked", msgType, chain[0].getSubjectDN().getName());
      }
      else if (e instanceof CertificateExpiredException) {
        event("CertificateExpired", msgType, chain[0].getSubjectDN().getName());
      }
      else if (e instanceof CertificateChainException) {
        event("CertificateChainUntrusted", msgType, chain[0].getSubjectDN().getName());
      }
      throw e;
    }
  }


  /**
   * Given the partial or complete certificate chain provided by the peer,
   * build a certificate path to a trusted root and return if it
   * can be validated and is trusted for server SSL authentication based on
   * the authentication type.
   */
  public void checkServerTrusted(X509Certificate[] chain, String authType)
    throws CertificateException
  {
    // check whether cert is valid, then build the chain
    if (log.isDebugEnabled()) {
      log.debug("checkServerTrusted: " + SSLDebug.getCertsDnNames(chain));
    }

    if (chain == null || chain.length == 0) {
      log.warn("checkServerTrusted: No certificate present");
      throw new CertificateException("No certificate present");
    }

    // check whether cert is of type node or server
    // Need to check whether needAuth?
    X509Certificate srvcert = chain[0];
    String srvdn = srvcert.getSubjectDN().getName();
    String title = CertificateUtility.findAttribute(srvdn, "t");
    if (title == null || (!title.equals(CertificateCache.CERT_TITLE_NODE)
			  && !title.equals(CertificateCache.CERT_TITLE_SERVER))) {
      String s = "Wrong type of server certificate. Title=" + title;
      log.warn(s);
      throw new CertificateException(s);
    }

    try {
      checkChainTrust(chain);
      if (log.isDebugEnabled()) {
	log.debug("checkServerTrusted - Cert is trusted: "
		  + SSLDebug.getCertsDnNames(chain));
      }
    } catch (CertificateException e) {
      if (log.isDebugEnabled()) {
	log.info("checkServerTrusted - Cert is NOT trusted: "
		 + SSLDebug.getCertsDnNames(chain) + " Reason: " + e);
      }
      String msgType = "ClientTrustManager";
      if (e instanceof CertificateRevokedException) {
        event("CertificateRevoked", msgType, chain[0].getSubjectDN().getName());
      }
      else if (e instanceof CertificateExpiredException) {
        event("CertificateExpired", msgType, chain[0].getSubjectDN().getName());
      }
      else if (e instanceof CertificateChainException) {
        event("CertificateChainUntrusted", msgType, chain[0].getSubjectDN().getName());
      }
      throw e;
    }
  }

  private void checkChainTrust(X509Certificate[] chain)
    throws CertificateException
  {
    // Check the certificate trust of every certificate backwards from the top.
    // We do this because we may not have all the intermediate CAs, and we
    // may not be able to retrieve these certificates through LDAP.
    // Going backwards allows to add the certificates in the cache, one at a time.
    if (chain == null || chain.length == 0) {
      throw new CertificateException("Certificate chain does not contain a certificate");
    }
    CertificateCacheService cacheservice=(CertificateCacheService)
      serviceBroker.getService(this,
			       CertificateCacheService.class,
			       null);
   
    if(cacheservice==null) {
      log.warn("Unable to get Certificate cache Service in checkChainTrust");
    }
    
    try {
      for (int i = (chain.length - 1) ; i >= 0 ; i--) {
	keyRing.checkCertificateTrust(chain[i]);
	// Add the first certificate in the chain if it was not already in the cache.
	if (log.isDebugEnabled()) {
	  log.debug("Checked trust of " + chain[i].getSubjectDN().getName()
		    + ". Adding cert to the cache");
	}
	if(cacheservice!=null) {
	  cacheservice.addSSLCertificateToCache(chain[i]);
	}
	else {
	  log.warn("Unable to add SSL Certificate To Cache as Certificate cache Service is null in checkChainTrust");
	}
      }
    }
    catch (Exception e) {
      // for unzip & run there will be too many warnings
      if (issuers.length == 0) {
        if (System.getProperty("org.cougaar.core.autoconfig", "false").equals("true")) {
          return;
        } 
      }
      if (log.isWarnEnabled()) {
	  log.warn("Failed to verify certificate: "
		 + chain[0].getSubjectDN().getName()
		 + ". Reason: ", e);
      }

      if (e instanceof CertificateException) {
        throw (CertificateException)e;
      }
      CertificateException ex =
	new CertificateException("Failed to build chain.");
      ex.initCause(e);
      throw ex;
    }
  }

  void event(String status, String mgrType, String dn) {

    String cn = dn;
    try {
      cn = new X500Name(dn).getCommonName();
    }
    catch (Exception ex) {}
    String evt = "[STATUS] " + mgrType + "." + status + "(" + cn + ")";
    cacheservice.event(evt);
  }

  /**
   * Only the CA in the Cougaar society for now
   */
  public X509Certificate[] getAcceptedIssuers() {
    // get all CA from the client cryptoPolicy and their parent CAs
    // how about trusted CA?
    // since node configuration has only one CA, the issues will only
    // be one CA and the node itself
    if (log.isDebugEnabled()) {
      log.debug("getAcceptedIssuers: " + SSLDebug.getCertsDnNames(issuers));
    }
    return issuers;
  }
}
