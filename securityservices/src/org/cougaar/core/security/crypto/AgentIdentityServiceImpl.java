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

package org.cougaar.core.security.crypto;

import java.io.*;
import java.util.*;
import java.security.PrivateKey;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;

import java.lang.IllegalArgumentException;

// Cougaar core infrastructure
import org.cougaar.core.component.ServiceBrokerSupport;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import com.nai.security.util.CryptoDebug;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.services.identity.*;
import org.cougaar.core.security.services.acl.*;
import org.cougaar.core.security.services.crypto.*;
import com.nai.security.crypto.*;


public class AgentIdentityServiceImpl
  implements AgentIdentityService
{
  private EncryptionService encryptionService;
  private CryptoPolicyService cps;
  private KeyRingService keyRing;

  public AgentIdentityServiceImpl(EncryptionService encryptionService,
				  CryptoPolicyService cps,
				  KeyRingService keyRing)
  {
    this.encryptionService = encryptionService;
    this.cps = cps;
    this.keyRing = keyRing;
  }

  public void CreateCryptographicIdentity(String agentName,
					  RevocationCallBack clientCallBack)
    throws PendingRequestException,
    IdentityDeniedException {
  }

  public void HoldCryptographicIdentity(String agentName) {
  }


  public void RevokeCryptographicIdentity(String agentName) {
  }

  /** @param privKey        The private keys to wrap
   *  @param cert           The certificates to wrap
   *  @param signerPrivKey  The private key of the signer
   *  @param signerCert     The certificate of the signer
   *  @param rcvrCert       The certificate of the intended receiver
   */
  public TransferableIdentity initiateTransfer(String agent,
					       String sourceAgent,
					       String targetAgent)
  {

    /* 1 - Package the agent private and public keys.
     * 2 - Remove the agent keys from the local cache.
     * 3 - Remove the agent keys from the local keystore.
     * There should be a transaction here, otherwise we may end
     * up deleting keys before they have reached their destination.
     */

    SecureMethodParam policy;

    policy = cps.getSendPolicy(sourceAgent+":"+targetAgent);

    if (CryptoDebug.debug) {
      System.out.println("Wrapping keys");
    }

    // Retrieve keys of the agent
    PrivateKey agentPrivKey = keyRing.findPrivateKey(agent);
    Certificate agentCert = keyRing.findCert(agent);

    PrivateKey[] privKey = new PrivateKey[1];
    privKey[0] = agentPrivKey;
    Certificate[] cert = new Certificate[1];
    cert[0] = agentCert;
    
    KeySet keySet = new KeySet(privKey, cert);

    PublicKeyEnvelope envelope =
      encryptionService.signAndEncrypt(keySet,
				       sourceAgent, targetAgent,
				       policy);
    KeyIdentity keyIdentity =
      new KeyIdentity(envelope.getSender(),
		      envelope.getReceiver(),
		      envelope.getEncryptedSymmetricKey(),
		      envelope.getEncryptedObject());
    return keyIdentity;
  }

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private key of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  public void completeTransfer(TransferableIdentity identity,
				 String sourceAgent,
				 String targetAgent)
  {
    /* 1 - Extract the keys from the envelope.
     * 2 - Install keys in the local keystore.
     */

    SecureMethodParam policy = null;
    policy = cps.getReceivePolicy(sourceAgent+":"+targetAgent);

    KeySet keySet = null;

    if (identity instanceof KeyIdentity) {
      KeyIdentity keyIdentity = (KeyIdentity) identity;
      Object o = encryptionService.decryptAndVerify(sourceAgent, targetAgent,
						    keyIdentity, policy);

      if (!(o instanceof KeySet)) {
	// Error
      }
      else {
	keySet = (KeySet) o;
      }
    }

    //return keySet;
  }
}
