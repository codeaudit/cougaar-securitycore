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


package org.cougaar.core.security.test;

import java.io.Serializable;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;

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
