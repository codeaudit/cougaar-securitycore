/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package org.cougaar.core.security.test.crypto;

import java.io.*;
import java.util.*;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import com.ibm.security.pkcs12.PKCS12PFX;
import com.ibm.security.pkcs8.PrivateKeyInfo;
import com.ibm.security.pkcsutil.PKCSException;
import org.cougaar.core.security.util.CryptoDebug;

// Cougaar Security Services
import org.cougaar.core.security.crypto.KeyRing;
import org.cougaar.core.security.crypto.PrivateKeyCert;
import org.cougaar.core.security.crypto.KeySet;
import org.cougaar.core.security.crypto.KeyWrapping;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.identity.TransferableIdentity;
import org.cougaar.core.security.services.identity.AgentIdentityService;
import org.cougaar.core.security.provider.SecurityServiceProvider;

public class AgentMobility
{
  private SecurityServiceProvider secProvider = null;
  private KeyRingService keyRing = null;
  private AgentIdentityService agentIdentity = null;

  public AgentMobility()
  {
    secProvider = new SecurityServiceProvider();

    keyRing = (KeyRingService)secProvider.getService(null,
						     this,
						     KeyRingService.class);

  }

  /** Test code only. */
  public static void main(String[] args) {
    /* args[0] : alias of signer
     * args[1] : alias of key to put in PKCS#12
     * args[2] : alias of receiver
     */

    AgentMobility m = new AgentMobility();

    m.testAgentMobility(args);
  }

  public void testAgentMobility(String[] args) {
    String signerAlias = args[0];
    String pkcs12Alias = args[1];
    String receiverAlias = args[2];


    if (CryptoDebug.debug) {
      System.out.println("======== Wrapping key");
    }
    TransferableIdentity identity =
      agentIdentity.initiateTransfer(pkcs12Alias,
				     signerAlias,
				     receiverAlias);
    if (CryptoDebug.debug) {
      System.out.println("======== Unwrapping key");
    }
    KeySet keySet = null;
    agentIdentity.completeTransfer(identity,
				   signerAlias,
				   receiverAlias);
  }

  public void testAgentMobilityWithPkcs12(String[] args) {

    String signerAlias = args[0];
    String pkcs12Alias = args[1];
    String receiverAlias = args[2];


    if (CryptoDebug.debug) {
      System.out.println("======== Looking up agent's key to be wrapped");
    }
    PrivateKey privKey = keyRing.findPrivateKey(pkcs12Alias);
    X509Certificate cert =
      (X509Certificate)keyRing.findCert(pkcs12Alias);
    if (privKey == null) {
      System.out.println("Error: unable to get agent key");
      return;
    }

    if (CryptoDebug.debug) {
      System.out.println("========= Looking up key for sender node");
    }
    PrivateKey signerPrivKey = keyRing.findPrivateKey(signerAlias);
    if (signerPrivKey == null) {
      System.out.println("Error: unable to get key for sender node");
      return;
    }

    if (CryptoDebug.debug) {
      System.out.println("========= Looking up certificate for sender node");
    }
    X509Certificate signerCertificate =
      (X509Certificate)keyRing.findCert(signerAlias);
    if (signerCertificate == null) {
      System.out.println("Error: unable to get certificate for sender node");
      return;
    }

    if (CryptoDebug.debug) {
      System.out.println("======== Looking up key for receiver node");
    }
    PrivateKey rcvrPrivKey = keyRing.findPrivateKey(receiverAlias);
    if (rcvrPrivKey == null) {
      System.out.println("Unable to get receiver node private key");
      return;
    }
    X509Certificate rcvrCert =
      (X509Certificate)keyRing.findCert(receiverAlias);

    java.security.PublicKey pubKey = rcvrCert.getPublicKey();
    String alg = rcvrCert.getPublicKey().getAlgorithm();

    if (CryptoDebug.debug) {
      System.out.println("Encryption parameters: " + alg);
    }

    /*
     * Disabled. This does not work yet.
    if (CryptoDebug.debug) {
      System.out.println("======== Wrapping agent's key:");
    }
    try {
      javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(alg);
      cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, pubKey);
      cipher.doFinal(privKey.getEncoded());
    }
    catch(Exception e) {
      if (CryptoDebug.debug) {
	System.out.println("Key encryption error (" + e.toString() + ")");
	e.printStackTrace();
      }
    }
    */

    if (CryptoDebug.debug) {
      System.out.println("==================================");
      System.out.println("======== Creating PKCS#12 envelope");
    }
    byte[] pkcs12 = keyRing.protectPrivateKey(privKey,
					      cert,
					      signerPrivKey,
					      signerCertificate,
					      rcvrCert);

    if (CryptoDebug.debug) {
      System.out.println("====================================");
      System.out.println("======== Extracting PKCS#12 envelope");
    }
    PrivateKeyCert[] pkey = keyRing.getPfx(pkcs12,
					   rcvrPrivKey,
					   rcvrCert);
  }
}
