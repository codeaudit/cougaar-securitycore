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
import javax.naming.*;

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
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.util.*;

/** A common holder for Security keystore information and functionality
 */

final public class KeyRing
  implements KeyRingService
{
  // keystore stores private keys and well-know public keys
  private DirectoryKeyStore directoryKeystore;
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

  private void init() {
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

    String installpath = secprop.getProperty(secprop.COUGAAR_INSTALL_PATH);

    String role =
      secprop.getProperty(secprop.SECURITY_ROLE);
    if (role == null && log.isInfoEnabled() == true) {
      log.info("Role is not defined");
    }
    SecurityPolicy[] sp =
      configParser.getSecurityPolicies(CryptoClientPolicy.class);
    CryptoClientPolicy cryptoClientPolicy = (CryptoClientPolicy) sp[0];

    if (cryptoClientPolicy == null
	|| cryptoClientPolicy.getCertificateAttributesPolicy() == null) {
      // This is OK for standalone applications if they don't plan to use
      // certificates for authentication, but it's not OK for nodes
      boolean exec =
	Boolean.valueOf(System.getProperty("org.cougaar.core.security.isExecutedWithinNode")).booleanValue();
      if (exec == true) {
	log.warn("Unable to get crypto Client policy");
      }
      else {
	log.info("Unable to get crypto Client policy");
      }
      throw new RuntimeException("Unable to get crypto Client policy");
    }
    
    param = new DirectoryKeyStoreParameters();
    param.serviceBroker = serviceBroker;

    // LDAP certificate directory
    param.isCertAuth = configParser.isCertificateAuthority();

    TrustedCaPolicy[] trustedCaPolicy = cryptoClientPolicy.getTrustedCaPolicy();
    
    if (trustedCaPolicy.length > 0) {
      if (log.isDebugEnabled()) {
	 log.debug(" TrustedCaPolicy is  :"+ trustedCaPolicy[0].toString());
       }
      param.ldapServerUrl = trustedCaPolicy[0].certDirectoryUrl;
      param.ldapServerType = trustedCaPolicy[0].certDirectoryType;
    }
    else {
       if (log.isDebugEnabled()) {
	 log.debug(" TrustedCaPolicy is Empty !!!!!!!!!!!!!!!!!!!!!!!! ");
       }
      
    }
    if(param.isCertAuth) {
       if (log.isDebugEnabled()) {
	 log.debug(" is Cert  Authority ----------------------------------------:");
       }
      
      X500Name [] caDNs=configParser.getCaDNs();
      if (caDNs.length > 0) {
        String caDN=caDNs[0].getName();
        CaPolicy capolicy=configParser.getCaPolicy(caDN);
        param.ldapServerUrl =capolicy.ldapURL;
        param.ldapServerType =capolicy.ldapType;
	param.defaultCaDn = caDN;
      }
      else {
	log.debug(" caDNs is empty !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!-:"+ caDNs.length);
      }
    }
    if (log.isDebugEnabled()) {
      log.debug(" Ladap type is :"+ param.ldapServerType); 
     }


    directoryKeystore = new DirectoryKeyStore(param);
    pkcs12 = new PrivateKeyPKCS12(directoryKeystore, serviceBroker);

    if (directoryKeystore == null || pkcs12 == null && param.isCertAuth == false) {
      // Cannot proceed without keystore
      boolean exec =
	Boolean.valueOf(System.getProperty("org.cougaar.core.security.isExecutedWithinNode")).booleanValue();
      if (exec == true) {
	log.error("Cannot continue secure execution without cryptographic data files");
      }
      else {
	log.info("Cryptographic keystores are missing");
      }
      throw new RuntimeException("No cryptographic keystores");
    }
  }
  
  /*
  public KeyStore getKeyStore() {
    if (directoryKeystore == null) {
      return null;
    }
    return directoryKeystore.getKeyStore();
  }
  */

  public DirectoryKeyStore getDirectoryKeyStore() {
    return directoryKeystore;
  }

  public List findPrivateKey(String cougaarName) {
    return findPrivateKey(cougaarName, true);
  }

  public List findPrivateKey(String cougaarName, boolean validOnly) {
    if (directoryKeystore == null) {
      return null;
    }
    return directoryKeystore.findPrivateKey(cougaarName, validOnly);
  }

  public List findPrivateKey(X500Name x500name) {
    if (directoryKeystore == null) {
      return null;
    }
    return directoryKeystore.findPrivateKey(x500name);
  }

  public List findCert(Principal p) {
    if (directoryKeystore == null) {
      return null;
    }
    return directoryKeystore.findCert(p);
  }

  public List findCert(String cougaarName) {
    if(log.isDebugEnabled()) {
      log.debug("Looking for cougaar name " + cougaarName + " in keystore ");
    }
    return directoryKeystore.findCert(cougaarName);
  }

  /**
   * @param cougaarName The common name of the entity
   * @param lookupType  The type of lookup.
   *  One of LOOKUP_LDAP, LOOKUP_KEYSTORE and LOOKUP_FORCE_LDAP_REFRESH
   */
  public List findCert(String cougaarName, int lookupType) {
    return findCert(cougaarName, lookupType, true);
  }

  /**
   * @param cougaarName The common name of the entity
   * @param lookupType  The type of lookup.
   *  One of LOOKUP_LDAP, LOOKUP_KEYSTORE and LOOKUP_FORCE_LDAP_REFRESH
   * @param validOnly   True: only valid certificates. False: all certificates
   */
  public List findCert(String cougaarName,
		       int lookupType, boolean validOnly) {
    if(log.isDebugEnabled())
      log.debug("Looking for cougaar name " + cougaarName
		+ " type = " + lookupType);
    List c = directoryKeystore.findCert(cougaarName, lookupType, validOnly);
    return c;
  }

  public Hashtable findCertPairFromNS(String source, String target)
    throws CertificateException {
    return directoryKeystore.findCertPairFromNS(source, target);
  }

  public List findDNFromNS(String name) {
    return directoryKeystore.findDNFromNS(name);
  }

  public List findCert(X500Name dname, int lookupType, boolean validOnly) {
    return directoryKeystore.findCert(dname, lookupType, validOnly);
  }

  public X509Certificate[] findCertChain(X509Certificate c)
  {
    X509Certificate[] chain = null;
    if (c == null) {
      return null;
    }
    try {
      chain = directoryKeystore.checkCertificateTrust(c);
    }
    catch (Exception e) {
    }
    return chain;
  }

  /*
  public void setSleeptime(long sleeptime)
  {
    if (directoryKeystore == null) {
      return;
    }
    directoryKeystore.setSleeptime(sleeptime);
  }

  public long getSleeptime()
  {
    if (directoryKeystore == null) {
      return -1;
    }
    return directoryKeystore.getSleeptime();
  }
  */

  public Vector getCRL()
  {
    if (directoryKeystore == null) {
      return null;
    }
    return null;
    //return directoryKeystore.getCRL();
  }

  public void checkOrMakeCert(String name)
  {
    if (directoryKeystore == null) {
      return;
    }
    directoryKeystore.checkOrMakeCert(name);
    return;
  }

  public void checkOrMakeCert(X500Name dname)
  {
    if (directoryKeystore == null) {
      return;
    }
    directoryKeystore.checkOrMakeCert(dname, false);
    return;
  }

  public void checkOrMakeCert(X500Name dname, boolean isCACert) {
    if (directoryKeystore == null) {
      return;
    }
    directoryKeystore.checkOrMakeCert(dname, isCACert);
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
    directoryKeystore.removeEntry(cougaarName);
  }

  public void setKeyEntry(PrivateKey key, X509Certificate cert) {
    directoryKeystore.setKeyEntry(key, cert);
  }

  /*
  public String getCommonName(String alias) {
    return directoryKeystore.getCommonName(alias);
  }
  public Enumeration getAliasList() {
    return directoryKeystore.getAliasList();
  }
*/
  public String getAlias(X509Certificate clientX509) {
    return directoryKeystore.getAlias(clientX509);
  }
  public  String parseDN(String aDN) {
    return directoryKeystore.parseDN(aDN);
  }

  public X509Certificate[] checkCertificateTrust(X509Certificate certificate)
    throws CertificateChainException, CertificateExpiredException,
    CertificateNotYetValidException, CertificateRevokedException {
    return directoryKeystore.checkCertificateTrust(certificate);
  }

  public X509Certificate[] buildCertificateChain(X509Certificate certificate) {
    return directoryKeystore.buildCertificateChain(certificate);
  }
  
  public boolean checkCertificate(CertificateStatus cs,
				  boolean buildChain, boolean changeStatus) {
    if(directoryKeystore!=null) {
      return directoryKeystore.checkCertificate(cs,buildChain,changeStatus);
    }
    return false;
					       
    
  }
  public  List getValidCertificates(X500Name x500Name) {
     if(directoryKeystore!=null) {
      return directoryKeystore.getValidCertificates(x500Name);
    }
    return null;
  }
/*
  public String getCaKeyStorePath() {
    return param.caKeystorePath;
  }
  
  public String getKeyStorePath() {
    return param.keystorePath;
  }
  */

  public boolean checkExpiry(String commonName) {
    return directoryKeystore.checkExpiry(commonName);
  }

  public void updateNS(String commonName) {
    directoryKeystore.updateNS(commonName);
  }

  public void updateNS(X500Name x500name) {
    directoryKeystore.updateNS(x500name);
  }
  public  CertDirectoryServiceClient getCACertDirServiceClient(String dname) {
    return directoryKeystore.getCACertDirServiceClient(dname);
  }

  public void checkOrMakeCert(X500Name dname, boolean isCACert, TrustedCaPolicy tc) {
    if (directoryKeystore == null) {
      return;
    }
    directoryKeystore.checkOrMakeCert(dname, isCACert, tc);
    return;
  }

/*
  public void addSSLCertificateToCache(X509Certificate cert) {
    directoryKeystore.addSSLCertificateToCache(cert);
  }
  
  public void removeEntryFromCache(String commonName) {
    directoryKeystore.removeEntryFromCache(commonName);
  }
*/
}

