/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 *
 * Created on September 12, 2001, 10:55 AM
 */

package org.cougaar.core.security.crypto;

import java.io.*;
import java.util.*;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Principal;
import java.security.cert.*;
import java.security.KeyPair;
import javax.security.auth.x500.X500Principal;

import sun.security.pkcs.*;
import sun.security.x509.*;
import sun.security.util.ObjectIdentifier;

// Cougaar core infrastructure
import org.cougaar.util.ConfigFinder;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

// Cougaar security services
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.provider.SecurityServiceProvider;

/** A common holder for Security keystore information and functionality
 **/

final public class KeyRing
  implements KeyRingService
{
  // keystore stores private keys and well-know public keys
  private DirectoryKeyStore keystore;
  private DirectoryKeyStoreParameters param;
  private boolean debug = false;
  private PrivateKeyPKCS12 pkcs12;
  private SecurityPropertiesService secprop = null;
  private ServiceBroker serviceBroker;
  private ConfigParserService configParser = null;
  private NodeConfiguration nodeConfiguration;
  private LoggingService log;

  public KeyRing(ServiceBroker sb) {
    serviceBroker = sb;
    init();
  }

  private synchronized void init() {
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class,
			       null);
    configParser = (ConfigParserService)
      serviceBroker.getService(this,
			       ConfigParserService.class,
			       null);
    if (secprop == null) {
      throw new RuntimeException("unable to get security properties service");
    }
    if (configParser == null) {
      throw new RuntimeException("unable to get config parser service");
    }

    try {
      String installpath = secprop.getProperty(secprop.COUGAAR_INSTALL_PATH);

      String role =
	secprop.getProperty(secprop.SECURITY_ROLE);
      if (role == null && log.isWarnEnabled() == true) {
	log.warn("Keyring Warning: LDAP role not defined");
      }
      SecurityPolicy[] sp =
	configParser.getSecurityPolicies(CryptoClientPolicy.class);
      CryptoClientPolicy cryptoClientPolicy = (CryptoClientPolicy) sp[0];

      // Keystore to store key pairs
      param = new DirectoryKeyStoreParameters();
      param.serviceBroker = serviceBroker;

      /*
      String defaultKeystorePath = installpath + File.separatorChar
	+ "configs" + File.separatorChar + "common"
	+ File.separatorChar + "keystore";
      param.keystorePassword =
	secprop.getProperty(secprop.KEYSTORE_PASSWORD,
			   "alpalp").toCharArray();
      param.keystorePath =
	secprop.getProperty(secprop.KEYSTORE_PATH,
			     defaultKeystorePath);
      */
      String nodeDomain = cryptoClientPolicy.getCertificateAttributesPolicy().domain;
      nodeConfiguration = new NodeConfiguration(nodeDomain, serviceBroker);
      param.keystorePath = nodeConfiguration.getNodeDirectory()
	+ cryptoClientPolicy.getKeystoreName();
      log.debug("going to use smart card: " + cryptoClientPolicy.getUseSmartCard());
      if (cryptoClientPolicy.getUseSmartCard()) {
        try {
          param.keystorePassword = 
            SmartCardApplet.getKeystorePassword(cryptoClientPolicy.getKeystorePassword(),
                                                log);
          
        } catch (RuntimeException e) {
          log.error("Couldn't talk to the keystore");
          throw e;
        }
      } else {
        param.keystorePassword = cryptoClientPolicy.getKeystorePassword().toCharArray();
      } // end of else

      File file = new File(param.keystorePath);
      if (!file.exists()){
	if (log.isInfoEnabled()) {
	  log.info(param.keystorePath +
		   " keystore does not exist. Creating...");
	}
        KeyStore k = KeyStore.getInstance(KeyStore.getDefaultType());
        FileOutputStream fos = new FileOutputStream(param.keystorePath);
	k.load(null, param.keystorePassword);
        k.store(fos, param.keystorePassword);
	fos.close();

      }
      param.keystoreStream = new FileInputStream(param.keystorePath);
      param.isCertAuth = configParser.isCertificateAuthority();

      // CA keystore parameters
      ConfigFinder configFinder = ConfigFinder.getInstance();
      param.caKeystorePath = nodeConfiguration.getNodeDirectory()
	+ cryptoClientPolicy.getTrustedCaKeystoreName();
      param.caKeystorePassword =
	cryptoClientPolicy.getTrustedCaKeystorePassword().toCharArray();

      if (log.isDebugEnabled()) {
	log.debug("CA keystorePath=" + param.caKeystorePath);
      }
      File cafile = new File(param.caKeystorePath);
      if (!cafile.exists()) {
	if (log.isInfoEnabled()) {
	  log.info(param.caKeystorePath +
			     "Trusted CA keystore does not exist. in "
			     + param.caKeystorePath + ". Trying with configFinder");
	}
	File cafile2 = configFinder.locateFile(cryptoClientPolicy.getTrustedCaKeystoreName());
	if (cafile2 != null) {
	  param.caKeystorePath = cafile2.getPath();
	}
	else {
	  if (param.isCertAuth) {
	    if (log.isInfoEnabled()) {
	      log.info(param.caKeystorePath +
		       " Trusted CA keystore does not exist. Creating...");
	    }
	    KeyStore k = KeyStore.getInstance(KeyStore.getDefaultType());
	    FileOutputStream fos = new FileOutputStream(param.caKeystorePath);
	    k.load(null, param.caKeystorePassword);
	    k.store(fos, param.caKeystorePassword);
	    fos.close();
	  }
	  else {
	    log.error("CA keystore unavailable. At least one CA certificate should be included");
	  }
	}
      }

      try {
	param.caKeystoreStream = new FileInputStream(param.caKeystorePath);
      }
      catch (Exception e) {
	if (log.isWarnEnabled()) {
	  log.warn("Warning: Could not open CA keystore ("
		    + param.caKeystorePath + "):" + e);
	}
	param.caKeystoreStream = null;
	param.caKeystorePath = null;
	param.caKeystorePassword = null;
      }

      if (log.isDebugEnabled()) {
	log.debug("Secure message keystore: path="
		  + param.keystorePath);
	log.debug("Secure message CA keystore: path="
		  + param.caKeystorePath);
      }

      // LDAP certificate directory
      TrustedCaPolicy[] trustedCaPolicy = cryptoClientPolicy.getTrustedCaPolicy();
      if (trustedCaPolicy.length > 0) {
	param.ldapServerUrl = trustedCaPolicy[0].certDirectoryUrl;
	param.ldapServerType = trustedCaPolicy[0].certDirectoryType;
      }

      keystore = new DirectoryKeyStore(param);

      if (param.keystoreStream != null) {
	param.keystoreStream.close();
      }
      if (param.caKeystoreStream != null) {
	param.caKeystoreStream.close();
      }

      pkcs12 = new PrivateKeyPKCS12(keystore, serviceBroker);

    } catch (Exception e) {
      e.printStackTrace();
    }
    if (keystore == null || pkcs12 == null && param.isCertAuth == false) {
      // Cannot proceed without keystore
      System.err.println("ERROR: Cannot continue secure execution");
      System.err.println("       without cryptographic data files");
      throw new RuntimeException("No cryptographic keystores");
    }
  }

  public synchronized KeyStore getKeyStore() {
    if (keystore == null) {
      return null;
    }
    return keystore.getKeyStore();
  }

  public synchronized DirectoryKeyStore getDirectoryKeyStore() {
    return keystore;
  }

  public synchronized List findPrivateKey(String cougaarName) {
    return findPrivateKey(cougaarName, true);
  }

  public synchronized List findPrivateKey(String cougaarName, boolean validOnly) {
    if (keystore == null) {
      return null;
    }
    return keystore.findPrivateKey(cougaarName, validOnly);
  }

  public synchronized List findPrivateKey(X500Name x500name) {
    if (keystore == null) {
      return null;
    }
    return keystore.findPrivateKey(x500name);
  }

  public synchronized List findCert(Principal p) {
    if (keystore == null) {
      return null;
    }
    return keystore.findCert(p);
  }

  public synchronized List findCert(String cougaarName) {
    if(log.isDebugEnabled())
      log.debug("Looking for cougaar name " + cougaarName + " in keystore ");
    return keystore.findCert(cougaarName);
  }

  /**
   * @param lookupType -
   */
  public synchronized List findCert(String cougaarName, int lookupType) {
    return findCert(cougaarName, lookupType, true);
  }

  public synchronized List findCert(String cougaarName, int lookupType, boolean validOnly) {
    if(log.isDebugEnabled())
      log.debug("Looking for cougaar name " + cougaarName
		+ " type = " + lookupType);
    List c = keystore.findCert(cougaarName, lookupType, validOnly);
    return c;
  }

  public synchronized X509Certificate[] findCertChain(X509Certificate c)
  {
    X509Certificate[] chain = null;
    if (c == null) {
      return null;
    }
    try {
      chain = keystore.checkCertificateTrust(c);
    }
    catch (Exception e) {
    }
    return chain;
  }

  public synchronized void setSleeptime(long sleeptime)
  {
    if (keystore == null) {
      return;
    }
    keystore.setSleeptime(sleeptime);
  }

  public synchronized long getSleeptime()
  {
    if (keystore == null) {
      return -1;
    }
    return keystore.getSleeptime();
  }

  public synchronized Vector getCRL()
  {
    if (keystore == null) {
      return null;
    }
    return null;
    //return keystore.getCRL();
  }

  public synchronized void checkOrMakeCert(String name)
  {
    if (keystore == null) {
      return;
    }
    keystore.checkOrMakeCert(name);
    return;
  }

  public synchronized void checkOrMakeCert(X500Name dname)
  {
    if (keystore == null) {
      return;
    }
    keystore.checkOrMakeCert(dname);
    return;
  }

  public synchronized void checkOrMakeCert(X500Name dname, boolean isCACert) {
    if (keystore == null) {
      return;
    }
    keystore.checkOrMakeCert(dname, isCACert);
    return;
  }

  /** @param privKey        The private keys to store in a PKCS#12 enveloppe
   *  @param cert           The certificate to store in a PKCS#12 enveloppe
   *  @param signerPrivKey  The private key of the signer
   *  @param signerCert     The certificate of the signer
   *  @param rcvrCert       The certificate of the intended receiver
   */
  public byte[] protectPrivateKey(List privKey,
				  List cert,
				  PrivateKey signerPrivKey,
				  X509Certificate signerCert,
				  X509Certificate rcvrCert)
  {
    return pkcs12.protectPrivateKey(privKey,
				    cert,
				    signerPrivKey,
				    signerCert,
				    rcvrCert);
  }

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private keys of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  public PrivateKeyCert[] getPfx(byte[] pfxBytes,
					List rcvrPrivKey,
					List rcvrCert)
  {
    return pkcs12.getPfx(pfxBytes,
			 rcvrPrivKey,
			 rcvrCert);
  }

  public void removeEntry(String cougaarName) {
    if (log.isInfoEnabled()) {
      log.info("Removing entry from keystore");
    }
    keystore.removeEntry(cougaarName);
  }

  public void setKeyEntry(PrivateKey key, X509Certificate cert) {
    keystore.setKeyEntry(key, cert);
  }

  public String getCommonName(String alias) {
    return keystore.getCommonName(alias);
  }

  public Enumeration getAliasList() {
    return keystore.getAliasList();
  }
  public String getAlias(X509Certificate clientX509) {
    return keystore.getAlias(clientX509);
  }
  public  String parseDN(String aDN) {
    return keystore.parseDN(aDN);
  }

  public X509Certificate[] checkCertificateTrust(X509Certificate certificate)
    throws CertificateChainException, CertificateExpiredException,
    CertificateNotYetValidException, CertificateRevokedException {
    return keystore.checkCertificateTrust(certificate);
  }

  public String getCaKeyStorePath() {
    return param.caKeystorePath;
  }
  public String getKeyStorePath() {
    return param.keystorePath;
  }

  public boolean checkExpiry(String commonName) {
    return keystore.checkExpiry(commonName);
  }

  public void updateNS(String commonName) {
    keystore.updateNS(commonName);
  }

  public void updateNS(X500Name x500name) {
    keystore.updateNS(x500name);
  }
}

