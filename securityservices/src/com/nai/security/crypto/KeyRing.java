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
import com.nai.security.certauthority.CAClient;
import com.nai.security.policy.NodePolicy;

//import com.nai.security.certauthority.KeyManagement;

/** A common holder for Security keystore information and functionality
 **/

final public class KeyRing {
  // keystore stores private keys and well-know public keys
  private static DirectoryKeyStore keystore;
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
      String ksPass = System.getProperty("org.cougaar.security.keystore.password",
					 "alpalp");
      String ksPath = System.getProperty("org.cougaar.security.keystore",
					 defaultKeystorePath);
      File file = new File(ksPass);
      if (!file.exists()){
	if (debug) {
	  System.out.println("Could not find keystore in:" + ksPath + ". Creating...");
	}
        KeyStore k = KeyStore.getInstance(KeyStore.getDefaultType());
        FileOutputStream fos = new FileOutputStream(ksPath);
	k.load(null, ksPass.toCharArray());
        k.store(fos, ksPass.toCharArray());
	fos.close();
        
      }
      FileInputStream   kss = new FileInputStream(ksPath);
      
      // CA keystore parameters
      confParser = new ConfParser();
      String role = System.getProperty("org.cougaar.security.role"); 
      if (role == null && debug == true) {
	System.out.println("Keyring Warning: LDAP role not defined");
      }
      NodePolicy nodePolicy = confParser.readNodePolicy(role);
      ConfigFinder configFinder = new ConfigFinder();
      File f = configFinder.locateFile(nodePolicy.CA_keystore);
      String caksPass = null;
      String caksPath = null;
      if (f != null) {
	caksPath = f.getPath();
	caksPass = nodePolicy.CA_keystorePassword;
      }

      /*caksPass = System.getProperty("org.cougaar.security.cakeystore.password",
					   "alpalp");
       caksPath = System.getProperty("org.cougaar.security.cakeystore",
					   defaultCaKeystorePath);
      */
      FileInputStream cakss = null;
      try {
	cakss = new FileInputStream(caksPath);
      }
      catch (Exception e) {
	if (debug) {
	  System.out.println("Could not open CA keystore: " + e);
	}
	cakss = null;
	caksPass = null;
	caksPath = null;
      }

      if (debug) {
	System.out.println("Secure message keystore: path=" + ksPath);
	System.out.println("Secure message CA keystore: path=" + caksPath);
      }
    
      // LDAP certificate directory
      String provider_url = nodePolicy.certDirectoryURL;

      /* Old system property not used anymore:
	 System.getProperty("org.cougaar.security.ldapserver",
	 "ldap://localhost");
      */

      keystore = new DirectoryKeyStore(provider_url,
				       kss, ksPass.toCharArray(), ksPath,
				       cakss, caksPass.toCharArray(), caksPath, false);
      if (kss != null) {
	kss.close();
      }
      if (cakss != null) {
	cakss.close();
      }

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static KeyStore getKeyStore() { 
    return keystore.getKeyStore();
  }

  public static PrivateKey findPrivateKey(String commonName) {
    return keystore.findPrivateKey(commonName);
  }

  public static Certificate findCert(Principal p) {
    return keystore.findCert(p);
  }

  public static Certificate findCert(String commonName) {
    return keystore.findCert(commonName);
  }

  /** Lookup a certificate. If lookupLDAP is true, search in the keystore only.
   * Otherwise, search in the keystore then in the LDAP directory service.
   */
  public static Certificate findCert(String commonName, boolean lookupLDAP) {
    Certificate c = null;
    try {
      c = keystore.findCert(commonName, lookupLDAP);
    }
    catch (Exception e) {
    }
    return c;
  }

  public static void setSleeptime(long sleeptime)
  {
    keystore.setSleeptime(sleeptime);
  }

  public static long getSleeptime()
  {
    return keystore.getSleeptime();
  }

  public static Vector getCRL()
  {
    return keystore.getCRL();
  }

  public static void checkOrMakeCert(String name)
  {
      keystore.checkOrMakeCert(name);
      return;
  }
  /** Generate a PKCS10 request from a public key */
  //public static String generateSigningCertificateRequest(byte[] dervalue) {
  //  return keystore.generateSigningCertificateRequest(dervalue);
  //}
}

