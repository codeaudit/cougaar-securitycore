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

package com.nai.security.crypto;

import java.io.*;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Enumeration;
import java.util.ArrayList;
import java.util.Vector;
import java.util.Properties;
import java.util.Collection;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Principal;
import java.security.cert.*;
import java.security.KeyPair;

import sun.security.pkcs.*;
import sun.security.x509.OIDMap;
import sun.security.util.ObjectIdentifier;

// Cougaar core infrastructure
import org.cougaar.util.ConfigFinder;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import com.nai.security.policy.NodePolicy;
import com.nai.security.util.CryptoDebug;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
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
  private ConfParser confParser = null;
  private PrivateKeyPKCS12 pkcs12;
  private SecurityPropertiesService secprop = null;
  private ServiceBroker serviceBroker;

  public KeyRing(ServiceBroker sb) {
    serviceBroker = sb;
    init();
  }

  private synchronized void init() {
    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class,
			       null);
    try {
      String installpath = secprop.getProperty(secprop.COUGAAR_INSTALL_PATH);

      // Keystore to store key pairs
      String defaultKeystorePath = installpath + File.separatorChar
	+ "configs" + File.separatorChar + "common"
	+ File.separatorChar + "keystore";
      param = new DirectoryKeyStoreParameters();
      param.serviceBroker = serviceBroker;

      param.keystorePassword =
	secprop.getProperty(secprop.KEYSTORE_PASSWORD,
			   "alpalp").toCharArray();
      param.keystorePath =
	secprop.getProperty(secprop.KEYSTORE_PATH,
			     defaultKeystorePath);
      File file = new File(param.keystorePath);
      if (!file.exists()){
	if (CryptoDebug.debug) {
	  System.out.println(param.keystorePath +
			     " keystore does not exist. Creating...");
	}
        KeyStore k = KeyStore.getInstance(KeyStore.getDefaultType());
        FileOutputStream fos = new FileOutputStream(param.keystorePath);
	k.load(null, param.keystorePassword);
        k.store(fos, param.keystorePassword);
	fos.close();
        
      }
      param.keystoreStream = new FileInputStream(param.keystorePath);
      param.isCertAuth = false;
      
      // CA keystore parameters
      confParser = new ConfParser(null, param.isCertAuth);
      String role = secprop.getProperty(secprop.SECURITY_ROLE); 
      if (role == null && CryptoDebug.debug == true) {
	System.out.println("Keyring Warning: LDAP role not defined");
      }
      NodePolicy nodePolicy = confParser.readNodePolicy(role);
      ConfigFinder configFinder = new ConfigFinder();
      File f = configFinder.locateFile(nodePolicy.CA_keystore);
      if (f != null) {
	param.caKeystorePath = f.getPath();
	param.caKeystorePassword = nodePolicy.CA_keystorePassword.toCharArray();
      }

      try {
	param.caKeystoreStream = new FileInputStream(param.caKeystorePath);
      }
      catch (Exception e) {
	if (CryptoDebug.debug) {
	  System.out.println("Could not open CA keystore: " + e);
	}
	param.caKeystoreStream = null;
	param.caKeystorePath = null;
	param.caKeystorePassword = null;
      }

      if (CryptoDebug.debug) {
	System.out.println("Secure message keystore: path="
			   + param.keystorePath);
	System.out.println("Secure message CA keystore: path="
			   + param.caKeystorePath);
      }
    
      // LDAP certificate directory
      param.ldapServerUrl = nodePolicy.certDirectoryUrl;
      param.ldapServerType = nodePolicy.certDirectoryType;

      keystore = new DirectoryKeyStore(param);

      if (param.keystoreStream != null) {
	param.keystoreStream.close();
      }
      if (param.caKeystoreStream != null) {
	param.caKeystoreStream.close();
      }

      pkcs12 = new PrivateKeyPKCS12(keystore);

    } catch (Exception e) {
      e.printStackTrace();
    }
    if (keystore == null || pkcs12 == null && param.isCertAuth == false) {
      // Cannot proceed without keystore
      System.err.println("ERROR: Cannot continue secure execution");
      System.err.println("       without cryptographic data files");
      try {
	throw new RuntimeException("No cryptographic keystores");
      }
      catch (RuntimeException e) {
	e.printStackTrace();
      }
      System.exit(-1);
    }
  }

  public synchronized KeyStore getKeyStore() { 
    if (keystore == null) {
      return null;
    }
    return keystore.getKeyStore();
  }

  public synchronized PrivateKey findPrivateKey(String commonName) {
    if (keystore == null) {
      return null;
    }
    return keystore.findPrivateKey(commonName);
  }

  public synchronized Certificate findCert(Principal p) {
    if (keystore == null) {
      return null;
    }
    return keystore.findCert(p);
  }

  public synchronized Certificate findCert(String commonName) {
    if(CryptoDebug.debug)
      System.out.println("Looking for common name " + commonName + " in keystore ");
    return keystore.findCert(commonName);
  }

  public synchronized Certificate findCert(String commonName, int lookupType) {
    Certificate c = null;
    try {
      c = keystore.findCert(commonName, lookupType);
    }
    catch (Exception e) {
    }
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

  /** @param privKey        The private key to store in a PKCS#12 enveloppe
   *  @param cert           The certificate to store in a PKCS#12 enveloppe
   *  @param signerPrivKey  The private key of the signer
   *  @param signerCert     The certificate of the signer
   *  @param rcvrCert       The certificate of the intended receiver
   */
  public byte[] protectPrivateKey(PrivateKey privKey,
					 Certificate cert,
					 PrivateKey signerPrivKey,
					 Certificate signerCert,
					 Certificate rcvrCert)
  {
    return pkcs12.protectPrivateKey(privKey,
				    cert,
				    signerPrivKey,
				    signerCert,
				    rcvrCert);
  }

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private key of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  public PrivateKeyCert[] getPfx(byte[] pfxBytes,
					PrivateKey rcvrPrivKey,
					Certificate rcvrCert)
  {
    return pkcs12.getPfx(pfxBytes,
			 rcvrPrivKey,
			 rcvrCert);
  }

  public void removeEntry(String commonName) {
    keystore.removeEntry(commonName);
  }

  public void setKeyEntry(PrivateKey key, X509Certificate cert) {
    keystore.setKeyEntry(key, cert);
  }
}

