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
 * Created on September 12, 2001, 10:55 AM
 */

package com.nai.security.test;

import java.io.Serializable;
import java.security.*;
import java.util.HashMap;
import java.security.cert.CertificateException;
import javax.crypto.*;
import java.security.Provider;
import java.security.Security;
import java.util.*;

public class TestCrypto {
        
  public static void main(String[] args) {
    TestCrypto tc = new TestCrypto();
    String theString = args[0];
    SealedObject so = null;
    String spec = args[1];

    String providerName = "com.sun.crypto.provider.SunJCE";
    try {
      Class c = Class.forName(providerName);
      Object o = c.newInstance();
      if (o instanceof java.security.Provider) {
	Security.addProvider((java.security.Provider) o);
      }
    } catch (Exception e) {
      System.out.println("Exception: " + e);
      e.printStackTrace();
    }
    providerName = "cryptix.jce.provider.CryptixCrypto";
    try {
      Class c = Class.forName(providerName);
      Object o = c.newInstance();
      if (o instanceof java.security.Provider) {
	Security.addProvider((java.security.Provider) o);
      }
    } catch (Exception e) {
      System.out.println("Exception: " + e);
      e.printStackTrace();
    }

    printProviderProperties();

    try {
      KeyPair kp = tc.createKeyPair();
      so = tc.asymmEncrypt(kp, spec, theString);
    } catch (Exception e) {
      System.out.println("Exception: " + e);
      e.printStackTrace();
    }

    System.out.println("Sealed object: " + so);
  }

  public KeyPair createKeyPair() throws
  java.security.NoSuchAlgorithmException {
    System.out.println("Creating key pair...");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

    System.out.println("Creating secure random number...");
    SecureRandom r = SecureRandom.getInstance("SHA1PRNG");

    System.out.println("Initializing key pair generator...");
    kpg.initialize(1024, r);

    System.out.println("Creating key pair...");
    KeyPair kp = kpg.genKeyPair();

    PrivateKey priv = kp.getPrivate();
    System.out.println("Algorithm is " + priv.getAlgorithm());

    return kp;
  }

  public SealedObject asymmEncrypt(KeyPair kp, String spec, Serializable obj)
    throws RuntimeException, CertificateException,
	   java.security.NoSuchAlgorithmException,
	   java.security.InvalidKeyException, java.io.IOException,
	   javax.crypto.NoSuchPaddingException, javax.crypto.IllegalBlockSizeException {
    /* encrypt the secret key with receiver's public key */
    PublicKey key= kp.getPublic();
    if (spec==""||spec==null) spec=key.getAlgorithm();
    /*init the cipher*/
    Cipher ci = null;
    //ci=Cipher.getInstance(spec);

    //TEST
       Provider[] pv = Security.getProviders();
       for (int i = 0 ; i < pv.length ; i++) {
       System.out.println("Provider[" + i + "]: " + pv[i].getName());
       try {
       ci=Cipher.getInstance(spec, pv[i].getName());
       } catch (java.security.NoSuchAlgorithmException e) {
       System.out.println("Provider[" + i + "]: " + pv[i].getName() + " does not provide " + spec);
       } catch (java.security.NoSuchProviderException e) {
       System.out.println("No such provider");
       }
       }
    //   END TEST

    ci.init(Cipher.ENCRYPT_MODE,key);
    return new SealedObject(obj,ci);
  }
 
  public static void printProviderProperties() {
    Provider[] pv = Security.getProviders();
    for (int i = 0 ; i < pv.length ; i++) {
      System.out.println("Provider[" + i + "]: " + pv[i].getName() + " - Version: " + pv[i].getVersion());
      System.out.println(pv[i].getInfo());
    }
  }

    
}
