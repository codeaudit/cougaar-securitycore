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
import java.security.Principal;

import java.lang.IllegalArgumentException;
import sun.security.x509.*;

// Cougaar core infrastructure
import org.cougaar.core.component.ServiceBrokerSupport;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;

// Overlay
import org.cougaar.core.security.coreservices.identity.*;
import org.cougaar.core.service.AgentIdentityService;

// Cougaar security services
import org.cougaar.core.security.util.CryptoDebug;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.services.identity.*;
import org.cougaar.core.security.services.acl.*;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.crypto.*;


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

    if (this.encryptionService == null) {
       throw new RuntimeException("Encryption service not available");
    }     
    if (this.cps == null) {
       throw new RuntimeException("Policy service not available");
    }     
    if (this.keyRing == null) {
       throw new RuntimeException("KeyRing service not available");
    }     

  }

  public void CreateCryptographicIdentity(MessageAddress agent,
					  RevocationCallBack clientCallBack)
    throws PendingRequestException,
    IdentityDeniedException {
    keyRing.checkOrMakeCert(agent.getAddress());
  }

  public void CreateCryptographicIdentity(Principal p,
					  RevocationCallBack clientCallBack)
    throws PendingRequestException,
    IdentityDeniedException {
    try {
      X500Name dname = new X500Name(p.getName());
      keyRing.checkOrMakeCert(dname);
    }
    catch (IOException e) {
      System.out.println("ERROR: Unable to create identity:" + e);
    }
  }

  public void HoldCryptographicIdentity(MessageAddress agent) {
    throw new RuntimeException("Feature not yet implemented");
  }


  public void RevokeCryptographicIdentity(MessageAddress agent) {
    throw new RuntimeException("Feature not yet implemented");
  }

  /** @param privKey        The private keys to wrap
   *  @param cert           The certificates to wrap
   *  @param signerPrivKey  The private key of the signer
   *  @param signerCert     The certificate of the signer
   *  @param rcvrCert       The certificate of the intended receiver
   */
  public TransferableIdentity initiateTransfer(MessageAddress agent,
					       MessageAddress sourceAgent,
					       MessageAddress targetAgent)
  {

    /* Three steps:
     * 1 - Package the agent private and public keys.
     * 2 - Remove the agent keys from the local cache.
     * 3 - Remove the agent keys from the local keystore.
     * There should be a transaction here, otherwise we may end
     * up deleting keys before they have reached their destination.
     */

    /* Step 1 */
    if (CryptoDebug.debug) {
      System.out.println("Initiating key transfer of " + agent.getAddress()
			 + " from " + sourceAgent.getAddress()
			 + " to " + targetAgent.getAddress());
    }
    SecureMethodParam policy;

    policy = cps.getSendPolicy(sourceAgent.getAddress() + ":"
			       + targetAgent.getAddress());
    if (policy == null) {
       throw new RuntimeException("Could not find message policy between "
	+ sourceAgent.getAddress() + " and " + targetAgent.getAddress());
    }     

    // Retrieve keys of the agent
    List agentPrivKeyList = keyRing.findPrivateKey(agent.getAddress());

    if (agentPrivKeyList.size() == 0) {
      throw new RuntimeException("Could not find private keys for "
	+ agent.getAddress());
    }
    PrivateKey[] privKey = new PrivateKey[agentPrivKeyList.size()];
    for (int i = 0 ; i < agentPrivKeyList.size() ; i++) {
      privKey[i] = ((PrivateKeyCert)(agentPrivKeyList.get(i))).getPrivateKey();
    }

    List agentCertList = keyRing.findCert(agent.getAddress());
    if (agentCertList.size() == 0) {
      throw new RuntimeException("Could not find certificates for "
	+ agent.getAddress());
    }
    X509Certificate[] cert = new X509Certificate[agentCertList.size()];
    for (int i = 0 ; i < agentCertList.size() ; i++) {
      cert[i] = ((CertificateStatus)(agentCertList.get(i))).getCertificate();
    }
    
    KeySet keySet = new KeySet(privKey, cert);

    PublicKeyEnvelope envelope =
      encryptionService.signAndEncrypt(keySet,
				       sourceAgent.getAddress(),
				       targetAgent.getAddress(),
				       policy);
    KeyIdentity keyIdentity =
      new KeyIdentity(envelope.getSender(),
		      envelope.getReceiver(),
		      envelope.getEncryptedSymmetricKey(),
		      envelope.getEncryptedObject());

    /* Step 2 & 3 */
    keyRing.removeEntry(agent.getAddress());

    return keyIdentity;
  }

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private key of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  public void completeTransfer(TransferableIdentity identity,
			       MessageAddress sourceAgent,
			       MessageAddress targetAgent)
  {
    /* 1 - Extract the keys from the envelope.
     * 2 - Install keys in the local keystore.
     */

    /* Step 1 */
    if (CryptoDebug.debug) {
      System.out.println("Completing key transfer from "
			 + sourceAgent.getAddress()
			 + " to " + targetAgent.getAddress());
    }

    SecureMethodParam policy =
      cps.getReceivePolicy(sourceAgent.getAddress()
			   +":"
			   +targetAgent.getAddress());

    KeySet keySet = null;

    if (CryptoDebug.debug) {
      System.out.println("Encrypted TransferableIdentity is " +
			 identity.getClass().getName());
    }

    if (identity instanceof KeyIdentity) {
      KeyIdentity keyIdentity = (KeyIdentity) identity;
      if (CryptoDebug.debug) {
	System.out.println("Decrypting KeyIdentity");
      }
      Object o = encryptionService.decryptAndVerify(sourceAgent.getAddress(),
						    targetAgent.getAddress(),
						    keyIdentity, policy);

      if (CryptoDebug.debug) {
	System.out.println("Decrypted TransferableIdentity is " +
			 o.getClass().getName());
      }
      if (!(o instanceof KeySet)) {
	// Error
	if (CryptoDebug.debug) {
	  System.out.println("ERROR: unexpected TransferableIdentity");
	}
      }
      else {
	keySet = (KeySet) o;
	PrivateKey[]  privateKeys = keySet.getPrivateKeys();
	X509Certificate[] certificates = keySet.getCertificates();
	if (privateKeys != null) {
	  if (CryptoDebug.debug) {
	    System.out.println("KeySet contains " + privateKeys.length
			       + " private keys");
	  }
	}
	else {
	  return;
	}
	if (certificates != null) {
	  if (CryptoDebug.debug) {
	    System.out.println("KeySet contains " + certificates.length
			       + " certificates");
	  }
	}
	else {
	  return;
	}
	if (certificates.length != privateKeys.length) {
	  return;
	}
	/* Step 2 */
	for (int i = 0 ; i < certificates.length ; i++) {
	  keyRing.setKeyEntry(privateKeys[i], certificates[i]);
	}
      }
    }

  }
}
