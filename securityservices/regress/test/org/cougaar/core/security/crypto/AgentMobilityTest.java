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

package test.org.cougaar.core.security.test.crypto;

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

// Cougaar core infrastructure
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.SimpleMessageAddress;
import org.cougaar.core.service.identity.*;
import org.cougaar.core.component.ServiceBroker;

// Cougaar Security Services
import org.cougaar.core.security.util.CryptoDebug;
import org.cougaar.core.security.crypto.KeyRing;
import org.cougaar.core.security.crypto.PrivateKeyCert;
import org.cougaar.core.security.crypto.KeySet;
import org.cougaar.core.security.crypto.KeyWrapping;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.provider.SecurityServiceProvider;

import junit.framework.*;

// Regress
import test.org.cougaar.core.security.simul.BasicNode;

public class AgentMobilityTest
  extends TestCase
{
  private SecurityServiceProvider secProvider = null;
  private BasicNode bn;
  private KeyRingService keyRing = null;
  private AgentIdentityService agentIdentity = null;
  private ServiceBroker serviceBroker;

  public AgentMobilityTest(String name)
  {
    super(name);
  }

  public void setUp() {
    // Initialize Basic Node
    bn = new BasicNode();
    Assert.assertNotNull("Could not get Basic Node", bn);

    secProvider = bn.getSecurityServiceProvider();
    serviceBroker = bn.getServiceBroker();

    keyRing = (KeyRingService)
      serviceBroker.getService(this, KeyRingService.class, null);
    Assert.assertNotNull("Could not get KeyRingService", keyRing);

    agentIdentity = (AgentIdentityService)
      serviceBroker.getService(this, AgentIdentityService.class, null);
    Assert.assertNotNull("Could not get AgentIdentityService",
			 agentIdentity);
  }

  /** Test code only. */
  public void testAgentMobility() {
    String signerAlias = "theSender";
    String pkcs12Alias = "theSender";
    String receiverAlias = "theReceiver";
    testAgentMobility(signerAlias, pkcs12Alias, receiverAlias);
  }

  private void testAgentMobility(String signerAlias,
				 String pkcs12Alias,
				 String receiverAlias) {

    MessageAddress agent =
      SimpleMessageAddress.getSimpleMessageAddress(pkcs12Alias);
    MessageAddress signer =
      SimpleMessageAddress.getSimpleMessageAddress(signerAlias);
    MessageAddress receiver =
      SimpleMessageAddress.getSimpleMessageAddress(receiverAlias);

    System.out.println("======== Wrapping key");
    TransferableIdentity identity =
      agentIdentity.transferTo(receiver);

    Assert.assertNotNull("Unable to wrap key",
			 identity);

    System.out.println("======== Unwrapping key");
    KeySet keySet = null;
    try {
      agentIdentity.acquire(identity);
    }
    catch (Exception e) {
      Assert.assertTrue("Unable to reacquire key: " + e, false);
    }
  }

  private void testAgentMobilityWithPkcs12(String[] args) {

    String signerAlias = args[0];
    String pkcs12Alias = args[1];
    String receiverAlias = args[2];


    if (CryptoDebug.debug) {
      System.out.println("======== Looking up agent's key to be wrapped");
    }
    List privKeyList = keyRing.findPrivateKey(pkcs12Alias);

    List certList = keyRing.findCert(pkcs12Alias);
    if (privKeyList == null) {
      System.out.println("Error: unable to get agent key");
      return;
    }

    if (CryptoDebug.debug) {
      System.out.println("========= Looking up key for sender node");
    }
    List signerPrivKeyList = keyRing.findPrivateKey(signerAlias);
    PrivateKey signerPrivKey = ((PrivateKeyCert)signerPrivKeyList.get(0)).getPrivateKey();
    if (signerPrivKey == null) {
      System.out.println("Error: unable to get key for sender node");
      return;
    }

    if (CryptoDebug.debug) {
      System.out.println("========= Looking up certificate for sender node");
    }
    List signerCertificateList = keyRing.findCert(signerAlias);
    X509Certificate signerCertificate =
      ((CertificateStatus)signerCertificateList.get(0)).getCertificate();
    if (signerCertificate == null) {
      System.out.println("Error: unable to get certificate for sender node");
      return;
    }

    if (CryptoDebug.debug) {
      System.out.println("======== Looking up key for receiver node");
    }

    List rcvrPrivKeyList = keyRing.findPrivateKey(receiverAlias);
    PrivateKey rcvrPrivKey = ((PrivateKeyCert)rcvrPrivKeyList.get(0)).getPrivateKey();
    if (rcvrPrivKey == null) {
      System.out.println("Unable to get receiver node private key");
      return;
    }
    List rcvrCertList = keyRing.findCert(receiverAlias);
    X509Certificate rcvrCert =
      ((CertificateStatus)rcvrCertList.get(0)).getCertificate();

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
    byte[] pkcs12 = keyRing.protectPrivateKey(privKeyList,
					      certList,
					      signerPrivKey,
					      signerCertificate,
					      rcvrCert);

    if (CryptoDebug.debug) {
      System.out.println("====================================");
      System.out.println("======== Extracting PKCS#12 envelope");
    }
    PrivateKeyCert[] pkey = keyRing.getPfx(pkcs12,
					   rcvrPrivKeyList,
					   rcvrCertList);
  }
}
