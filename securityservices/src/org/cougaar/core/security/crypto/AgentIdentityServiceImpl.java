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
import javax.crypto.SealedObject;
import java.security.GeneralSecurityException;
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
import org.cougaar.core.agent.SimpleAgent;
import org.cougaar.core.plugin.SimplePlugin;
import org.cougaar.core.node.NodeAgent;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.service.LoggingService;

// Overlay
import org.cougaar.core.service.identity.*;

// Cougaar security services
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.services.acl.*;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.certauthority.servlet.*;
import org.cougaar.core.security.provider.ServletPolicyServiceProvider;


public class AgentIdentityServiceImpl
  implements AgentIdentityService
{
  private ServiceBroker serviceBroker;
  private EncryptionService encryptionService;
  private CryptoPolicyService cps;
  private KeyRingService keyRing;
  private CertValidityService cvs;
  private Object requestor;
  private MessageAddress requestorAddress;
  private boolean clientNameIsPrincipal;
  private MessageAddress thisNodeAddress;
  private LoggingService log;

  public AgentIdentityServiceImpl(ServiceBroker sb, Object requestor)
  {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    clientNameIsPrincipal = false;
    this.requestor = requestor;

    if (requestor instanceof SimpleAgent) {
      requestorAddress = ((SimpleAgent)requestor).getAgentIdentifier();
    }
    else if (requestor instanceof NodeAgent) {
      requestorAddress = ((NodeAgent)requestor).getAgentIdentifier();
    }
    else if (requestor instanceof AgentIdentityClient) {
      requestorAddress = new MessageAddress(((AgentIdentityClient)requestor).getName());
    clientNameIsPrincipal = true;
    }
    else {
      throw new RuntimeException ("Unable to service this requestor. Unsupported client:"
				  + requestor.getClass().getName());
    }
    // Get encryption service
    encryptionService = (EncryptionService)
      serviceBroker.getService(requestor,
			       EncryptionService.class,
			       null);

    // Get crypto policy service
    cps = (CryptoPolicyService)
      serviceBroker.getService(requestor,
			       CryptoPolicyService.class,
			       null);

    // Get keyring service
    keyRing = (KeyRingService)
      serviceBroker.getService(requestor,
			       KeyRingService.class,
			       null);

    // Get validity service
    cvs = (CertValidityService)
      serviceBroker.getService(requestor,
			       CertValidityService.class,
			       null);

    // Get NodeIdentification service
    NodeIdentificationService nodeId = (NodeIdentificationService)
      serviceBroker.getService(requestor,
			       NodeIdentificationService.class,
			       null);
    if (nodeId == null) {
      throw new RuntimeException("Node Identification service not available");
    }
    thisNodeAddress = nodeId.getNodeIdentifier();

    if (encryptionService == null) {
       throw new RuntimeException("Encryption service not available");
    }
    if (cps == null) {
       throw new RuntimeException("Policy service not available");
    }
    if (keyRing == null) {
       throw new RuntimeException("KeyRing service not available");
    }

  }

  public void acquire(TransferableIdentity transferableIdentity)
    throws PendingRequestException,
    IdentityDeniedException {
    if (log.isDebugEnabled()) {
      log.debug("acquire identity:"
		+ requestorAddress.toAddress());
    }
    // Add the agent to the list that the ServletPolicyEnforcer
    // has to keep track of for rules that deal with all agents.
    ServletPolicyServiceProvider.addAgent(requestorAddress.toAddress());
    if (transferableIdentity != null) {
      completeTransfer(transferableIdentity);
    }
    else {
      if (clientNameIsPrincipal) {
	try {
	  X500Name dname = null;
	  dname = new X500Name(requestorAddress.toAddress());
          boolean isCACert = (requestor instanceof CAIdentityClientImpl);
          if (!isCACert) {
            String cn = dname.getCommonName();
            String title = ", t=" + DirectoryKeyStore.getTitle(cn);
            dname = new X500Name(requestorAddress.toAddress() + title);
          }
	  keyRing.checkOrMakeCert(dname, isCACert);
	}
	catch (Exception e) {
	  if (log.isErrorEnabled()) {
	    log.error("Unable to get DN: " + e);
	  }
	}
      }
      else {
	keyRing.checkOrMakeCert(requestorAddress.toAddress());
        keyRing.updateNS(requestorAddress.toAddress());
        cvs.addValidityListener(
          new AgentValidityListener(requestorAddress.toAddress()));
      }
    }
  }

  public void release() {
    if (log.isDebugEnabled()) {
      log.debug("release identity:"
		+ requestorAddress.toAddress());
    }
  }

  /*
  public void acquireX500Identity(Principal p)
    throws PendingRequestException,
    IdentityDeniedException {
    try {
      X500Name dname = new X500Name(p.getName());
      keyRing.checkOrMakeCert(dname);
    }
    catch (IOException e) {
      log.error("ERROR: Unable to create identity:" + e);
    }
  }
  */

  /**
   * Prepare to move an agent to a remote node.
   */
  public TransferableIdentity transferTo(MessageAddress targetNode)
  {
    if (requestor instanceof NodeAgent) {
      throw new RuntimeException ("Move NodeAgent not supported");
    }

    /* Three steps:
     * 1 - Package the agent private and public keys.
     * 2 - Remove the agent keys from the local cache.
     * 3 - Remove the agent keys from the local keystore.
     * There should be a transaction here, otherwise we may end
     * up deleting keys before they have reached their destination.
     */

    /* Step 1 */
    if (log.isInfoEnabled()) {
      log.info("Initiating key transfer of " + requestorAddress.toAddress()
	       + " from " + thisNodeAddress.toAddress()
	       + " to " + targetNode.toAddress());
    }
    SecureMethodParam policy =
      new SecureMethodParam(SecureMethodParam.SIGNENCRYPT);
    policy.symmSpec = "DES";
    policy.asymmSpec = "RSA";
    policy.signSpec = "MD5withRSA";
    
/*      cps.getSendPolicy(thisNodeAddress.toAddress() + ":"
			  + targetNode.toAddress());
    if (policy == null) {
       throw new RuntimeException("Could not find message policy between "
	+ thisNodeAddress.toAddress() + " and " + targetNode.toAddress());
    }
*/
    // Retrieve private keys of the agent
    List agentPrivKeyList = keyRing.findPrivateKey(requestorAddress.toAddress());

    if (agentPrivKeyList.size() == 0) {
      throw new RuntimeException("Could not find private keys for "
	+ requestorAddress.toAddress());
    }
    PrivateKey[] privKey = new PrivateKey[agentPrivKeyList.size()];
    for (int i = 0 ; i < agentPrivKeyList.size() ; i++) {
      privKey[i] = ((PrivateKeyCert)(agentPrivKeyList.get(i))).getPrivateKey();
    }

    // Retrieve certificates
    List agentCertList = keyRing.findCert(requestorAddress.toAddress());
    if (agentCertList.size() == 0) {
      throw new RuntimeException("Could not find certificates for "
	+ requestorAddress.toAddress());
    }
    X509Certificate[] cert = new X509Certificate[agentCertList.size()];
    for (int i = 0 ; i < agentCertList.size() ; i++) {
      cert[i] = ((CertificateStatus)(agentCertList.get(i))).getCertificate();
    }

    KeySet keySet = new KeySet(privKey, cert);

    // Create a secure envelope with the agent keys and certificates
    PublicKeyEnvelope envelope = null;
    try {
      envelope = (PublicKeyEnvelope)
	encryptionService.protectObject(keySet,
					thisNodeAddress,
					targetNode,
					policy);
    }
    catch (GeneralSecurityException e) {
      if (log.isErrorEnabled()) {
	log.error("Unable to protect agent keys:" + e.toString());
      }
      return null;
    }
    catch (IOException e) {
      if (log.isErrorEnabled()) {
	log.error("Unable to protect agent keys" + e.toString());
      }
      return null;
    }

    KeyIdentity keyIdentity =
      new KeyIdentity(envelope.getSender(),
		      envelope.getReceiver(),
		      policy,
		      envelope.getEncryptedSymmetricKey(),
		      envelope.getEncryptedSymmetricKeySender(),
		      envelope.getObject());

    /* Step 3 */
    keyRing.removeEntry(requestorAddress.toAddress());

    return keyIdentity;
  }

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private key of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  private void completeTransfer(TransferableIdentity identity)
  {
    /* 1 - Extract the keys from the envelope.
     * 2 - Install keys in the local keystore.
     */

    if (log.isDebugEnabled()) {
      log.debug("Encrypted TransferableIdentity is " +
		identity.getClass().getName());
    }

    if (!(identity instanceof KeyIdentity)) {
      throw new RuntimeException("Unsupported TransferableIdentity:"
	+ identity.getClass().getName());
    }

    KeyIdentity ki = (KeyIdentity)identity;
    X500Name dname = null;
    String sender = null;
    try {
      dname = new X500Name(ki.getSender().getSubjectDN().getName());
      sender = dname.getCommonName();
    }
    catch (Exception e) {
      if (log.isErrorEnabled()) {
	log.error("Unable to get sender Common Name: " + e);
      }
      throw new RuntimeException("Unable to get sender information:"
				 + ki.getSender().getSubjectDN().getName());
    }

    /* Step 1 */
    if (log.isInfoEnabled()) {
      log.info("Completing key transfer from "
	       + sender
	       + " to " + thisNodeAddress.toAddress());
    }

    SecureMethodParam policy = 
      new SecureMethodParam(SecureMethodParam.SIGNENCRYPT);
    policy.symmSpec = "DES";
    policy.asymmSpec = "RSA";
    policy.signSpec = "MD5withRSA";
    
/*      cps.getReceivePolicy(sender
			   +":"
			   +thisNodeAddress.toAddress());
*/
    KeySet keySet = null;

    KeyIdentity keyIdentity = (KeyIdentity) identity;
    if (log.isDebugEnabled()) {
      log.debug("Decrypting KeyIdentity");
    }
    Object o = null;
    try {
      o = encryptionService.unprotectObject(new MessageAddress(sender),
					    thisNodeAddress,
					    keyIdentity, policy);
    }
    catch (GeneralSecurityException e) {
      return;
    }
    if (log.isDebugEnabled()) {
      log.debug("Decrypted TransferableIdentity is " +
		o.getClass().getName());
    }
    if (!(o instanceof KeySet)) {
      // Error
      if (log.isErrorEnabled()) {
	log.error("Unexpected TransferableIdentity");
      }
    }
    else {
      keySet = (KeySet) o;
      PrivateKey[]  privateKeys = keySet.getPrivateKeys();
      X509Certificate[] certificates = keySet.getCertificates();
      if (privateKeys != null) {
	if (log.isDebugEnabled()) {
	  log.debug("KeySet contains " + privateKeys.length
		    + " private keys");
	}
      }
      else {
	return;
      }
      if (certificates != null) {
	if (log.isDebugEnabled()) {
	  log.debug("KeySet contains " + certificates.length
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

  class AgentValidityListener implements CertValidityListener {
    String commonName;

    public AgentValidityListener(String commonName) {
      this.commonName = commonName;
    }

    public String getName() {
      return commonName;
    }

    /**
     * For agent everytime it communicates it calls findCert, no need for
     * updating certificate
     */
    public void updateCertificate() {}
  }

}
