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

import org.cougaar.util.ConfigFinder;
import com.nai.security.policy.NodePolicy;

//import com.nai.security.certauthority.KeyManagement;

/** A common holder for Security keystore information and functionality
 **/

final public class KeyRing {
  // keystore stores private keys and well-know public keys
  private static DirectoryKeyStore keystore;
  private static DirectoryKeyStoreParameters param;
  private static boolean debug = false;
  private static ConfParser confParser = null;

  static {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    init();
  }

  private static synchronized void init() {
    try {
      String installpath = System.getProperty("org.cougaar.install.path");

      // CA keystore: contains trusted certificates of Certificate Authorities
      String defaultCaKeystorePath = installpath + File.separatorChar
	+ "configs" + File.separatorChar + "common"
	+ File.separatorChar + "keystoreCA";

      // Keystore to store key pairs
      String defaultKeystorePath = installpath + File.separatorChar
	+ "configs" + File.separatorChar + "common"
	+ File.separatorChar + "keystore";
      param = new DirectoryKeyStoreParameters();
      param.keystorePassword =
	System.getProperty("org.cougaar.security.keystore.password",
			   "alpalp").toCharArray();
      param.keystorePath =
	System.getProperty("org.cougaar.security.keystore",
			     defaultKeystorePath);
      File file = new File(param.keystorePath);
      if (!file.exists()){
	if (debug) {
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
      
      // CA keystore parameters
      confParser = new ConfParser();
      String role = System.getProperty("org.cougaar.security.role"); 
      if (role == null && debug == true) {
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
	if (debug) {
	  System.out.println("Could not open CA keystore: " + e);
	}
	param.caKeystoreStream = null;
	param.caKeystorePath = null;
	param.caKeystorePassword = null;
      }

      if (debug) {
	System.out.println("Secure message keystore: path=" + param.keystorePath);
	System.out.println("Secure message CA keystore: path=" + param.caKeystorePath);
      }
    
      // LDAP certificate directory
      param.ldapServerUrl = nodePolicy.certDirectoryUrl;
      param.ldapServerType = nodePolicy.certDirectoryType;

      param.standalone = false;
      keystore = new DirectoryKeyStore(param);

      if (param.keystoreStream != null) {
	param.keystoreStream.close();
      }
      if (param.caKeystoreStream != null) {
	param.caKeystoreStream.close();
      }

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static synchronized KeyStore getKeyStore() { 
    if (keystore == null) {
      return null;
    }
    return keystore.getKeyStore();
  }

  public static synchronized PrivateKey findPrivateKey(String commonName) {
    if (keystore == null) {
      return null;
    }
    return keystore.findPrivateKey(commonName);
  }

  public static synchronized Certificate findCert(Principal p) {
    if (keystore == null) {
      return null;
    }
    return keystore.findCert(p);
  }

  public static synchronized Certificate findCert(String commonName) {
    if(debug)
      System.out.println("Looking for common name " + commonName + " in keystore ");
    return keystore.findCert(commonName);
  }

  public static synchronized Certificate findCert(String commonName, int lookupType) {
    Certificate c = null;
    try {
      c = keystore.findCert(commonName, lookupType);
    }
    catch (Exception e) {
    }
    return c;
  }

  public static synchronized X509Certificate[] findCertChain(X509Certificate c)
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

  public static synchronized void setSleeptime(long sleeptime)
  {
    if (keystore == null) {
      return;
    }
    keystore.setSleeptime(sleeptime);
  }

  public static synchronized long getSleeptime()
  {
    if (keystore == null) {
      return -1;
    }
    return keystore.getSleeptime();
  }

  public static synchronized Vector getCRL()
  {
    if (keystore == null) {
      return null;
    }
    return keystore.getCRL();
  }

  public static synchronized void checkOrMakeCert(String name)
  {
    if (keystore == null) {
      return;
    }
    keystore.checkOrMakeCert(name);
    return;
  }
}

