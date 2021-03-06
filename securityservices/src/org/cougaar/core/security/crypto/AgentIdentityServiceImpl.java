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


package org.cougaar.core.security.crypto;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.node.NodeAgent;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.security.certauthority.CAIdentityClientImpl;
import org.cougaar.core.security.provider.ServletPolicyServiceProvider;
import org.cougaar.core.security.services.crypto.CertValidityService;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.identity.AgentIdentityClient;
import org.cougaar.core.service.identity.AgentIdentityService;
import org.cougaar.core.service.identity.IdentityDeniedException;
import org.cougaar.core.service.identity.PendingRequestException;
import org.cougaar.core.service.identity.TransferableIdentity;

import sun.security.x509.X500Name;


public class AgentIdentityServiceImpl
  implements AgentIdentityService
{
  private ServiceBroker serviceBroker;
  private EncryptionService encryptionService;
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

      // cougaar 11.2 has changed to use AgentIdentityClient as requestor
/*
      if (requestor instanceof SimpleAgent) {
        requestorAddress = ((SimpleAgent)requestor).getAgentIdentifier();
      }
      else if (requestor instanceof NodeAgent) {
        requestorAddress = ((NodeAgent)requestor).getAgentIdentifier();
      }
      else */if (requestor instanceof AgentIdentityClient) {
        String identity = ((AgentIdentityClient)requestor).getName();
        requestorAddress = MessageAddress.getMessageAddress(identity);
//        requestorAddress = MessageAddress.getMessageAddress(((AgentIdentityClient)requestor).getName());
        
        clientNameIsPrincipal = true;
        // check to make sure whether it is X500Name
        if (identity.indexOf(',') == -1) {
          clientNameIsPrincipal = false;
        }
       
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
/*    cps = (CryptoPolicyService)
      serviceBroker.getService(requestor,
      CryptoPolicyService.class,
      null);
*/
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
      thisNodeAddress = nodeId.getMessageAddress();

      if (encryptionService == null) {
        throw new RuntimeException("Encryption service not available");
      }
/*    if (cps == null) {
      throw new RuntimeException("Policy service not available");
      }
*/    if (keyRing == null) {
  throw new RuntimeException("KeyRing service not available");
}

    }

  public void acquire(TransferableIdentity transferableIdentity)
    throws PendingRequestException,
    IdentityDeniedException {
    if (log.isDebugEnabled()) {
      log.debug("acquire identity:"
		+ requestorAddress.toAddress() + ". TransferableIdentity: " + transferableIdentity);
    }
    // Add the agent to the list that the ServletPolicyEnforcer
    // has to keep track of for rules that deal with all agents.
    ServletPolicyServiceProvider.addAgent(requestorAddress.toAddress());
    if (transferableIdentity != null) {
      // Complete agent mobility
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
            String title = ", t=" + CertificateCache.getTitle(cn);
            dname = new X500Name(requestorAddress.toAddress() + title);
          }
	  keyRing.checkOrMakeCert(dname, isCACert);
          if (isCACert) {
            keyRing.updateNS(dname);
          }
	}
	catch (Exception e) {
	  if (log.isErrorEnabled()) {
	    log.error("Unable to get DN: ", e);
	  }
	}
      }
      else {
	keyRing.checkOrMakeCert(requestorAddress.toAddress());
        
	// Update entry in naming service
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
    CertificateCacheService cacheservice=(CertificateCacheService)
      serviceBroker.getService(this,
                               CertificateCacheService.class,
                               null);

    if(cacheservice==null) {
      log.warn("Unable to get Certificate cache Service in release will not be able to remove entry from cache");
      return;
    }
    // Remove entry from certificate cache
    cacheservice.removeEntryFromCache(requestorAddress.toAddress());

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

      /*
        cps.getSendPolicy(thisNodeAddress.toAddress() + ":"
        + targetNode.toAddress());
        if (policy == null) {
        throw new RuntimeException("Could not find message policy between "
	+ thisNodeAddress.toAddress() + " and " + targetNode.toAddress());
        }
      */

      // Retrieve private keys of the agent
      List agentPrivKeyList =
        keyRing.findPrivateKey(requestorAddress.toAddress());

      if (agentPrivKeyList.size() == 0) {
        log.warn("Cannot move agent. Could not find private keys for " + requestorAddress.toAddress());
        throw new RuntimeException("Could not find private keys for "
                                   + requestorAddress.toAddress());
      }
      if (log.isDebugEnabled()) {
        log.debug("Moving " + agentPrivKeyList.size() + " private keys of " + requestorAddress.toAddress());
      }

      PrivateKey[] privKey = new PrivateKey[agentPrivKeyList.size()];
      for (int i = 0 ; i < agentPrivKeyList.size() ; i++) {
        privKey[i] = ((PrivateKeyCert)(agentPrivKeyList.get(i))).getPrivateKey();
      }

      // Retrieve certificates. Do not lookup certificates in LDAP, as there
      // may be old certificates.
      List agentCertList =
        keyRing.findCert(requestorAddress.toAddress(),
                         KeyRingService.LOOKUP_KEYSTORE);
      if (agentCertList.size() == 0) {
        log.warn("Cannot move agent. Could not find certificates for "
                 + requestorAddress.toAddress());
        throw new RuntimeException("Could not find certificates for "
                                   + requestorAddress.toAddress());
      }
      if (log.isDebugEnabled()) {
        log.debug("Moving " + agentCertList.size() + " certificate of " + requestorAddress.toAddress());
      }

      X509Certificate[] cert = new X509Certificate[agentCertList.size()];
      for (int i = 0 ; i < agentCertList.size() ; i++) {
        cert[i] = ((CertificateStatus)(agentCertList.get(i))).getCertificate();
      }

      KeySet keySet = null;
      try {
        keySet = new KeySet(privKey, cert);
      }
      catch (Exception e) {
        log.error("Cannot move agent ["
                  + requestorAddress.toAddress()
                  + "]. Unable to get private and public keys: " + e);
        throw new RuntimeException("Cannot move agent ["
                                   + requestorAddress.toAddress()
                                   + "]. Unable to get private and public keys: " + e);
      }

      if (log.isDebugEnabled()) {
        log.debug("Creating public key envelope for " + requestorAddress.toAddress());
      }

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
      if (envelope.getSenderAddress() == null || envelope.getReceiverAddress() == null) {
        log.warn("Unable to move " + requestorAddress.toAddress()
                 + " agent. Either sender or receiver is null");
        throw new RuntimeException("Unable to move " + requestorAddress.toAddress()
                                   + " agent. Either sender or receiver is null");
      }

      if (log.isDebugEnabled()) {
        log.debug("Creating KeyIdentity for " + requestorAddress.toAddress());
      }

      KeyIdentity keyIdentity =
        new KeyIdentity(envelope.getSender(),
                        envelope.getReceiver(),
                        thisNodeAddress,
                        targetNode,
                        policy,
                        envelope.getEncryptedSymmetricKeySender(),
                        envelope.getEncryptedSymmetricKey(),
                        envelope.getObject());

      if (log.isDebugEnabled()) {
        log.debug("Removing key entry for " + requestorAddress.toAddress());
      }

      /* Step 3 */
      keyRing.removeEntry(requestorAddress.toAddress());

      // Enable this only if BUG 2251 has been fixed
      if (log.isDebugEnabled()) {
        log.debug("Delete keys from cache: "
                  + requestorAddress.toAddress());
      }
      // Remove entry from certificate cache
      CertificateCacheService cacheservice=(CertificateCacheService)
        serviceBroker.getService(this,
                                 CertificateCacheService.class,
                                 null);

      if(cacheservice==null) {
        log.warn("Unable to get Certificate cache Service in transferTo ,will not be able to remove entry from cache");
        return keyIdentity;
      }
      cacheservice.removeEntryFromCache(requestorAddress.toAddress());

      if (log.isDebugEnabled()) {
        log.debug("Successfully returning KeyIdentity for " + requestorAddress.toAddress());
      }

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

      if (log.isInfoEnabled()) {
        log.info("CompleteTransfer. Encrypted TransferableIdentity is " +
                 identity.getClass().getName());
      }

      if (!(identity instanceof KeyIdentity)) {
        throw new RuntimeException("Unsupported TransferableIdentity:"
                                   + identity.getClass().getName());
      }

      KeyIdentity keyIdentity = (KeyIdentity)identity;
      if (keyIdentity == null) {
        log.warn("Unable to install moved agent. KeyIdentity is null");
        throw new RuntimeException("Unable to install moved agent. KeyIdentity is null");
      }
      MessageAddress sender = keyIdentity.getSenderAddress();
      if (sender == null) {
        log.warn("Unable to install moved agent. Sender identity is null");
        throw new RuntimeException("Unable to install moved agent. Sender identity is null");
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

      /*
        cps.getReceivePolicy(sender
        +":"
        +thisNodeAddress.toAddress());
      */
      KeySet keySet = null;
      if (log.isDebugEnabled()) {
        log.debug("Decrypting KeyIdentity");
      }
      Object o = null;
      try {
        o = encryptionService.unprotectObject(sender,
                                              thisNodeAddress,
                                              keyIdentity, policy);
      }
      catch (GeneralSecurityException e) {
        log.warn("Unable to decrypt KeyIdentity for moved agent:"
                 + sender.toAddress() + "->" + thisNodeAddress.toAddress());
        return;
      }
      if (o == null) {
        log.warn("TransferableIdentity could not be decrypted (null) " +
                 sender.toAddress() + "->" + thisNodeAddress.toAddress());
        return;
      }

      if (log.isDebugEnabled()) {
        log.debug("Decrypted TransferableIdentity is " +
                  o.getClass().getName());
      }
      if (!(o instanceof KeySet)) {
        // Error
        if (log.isErrorEnabled()) {
          log.error("Unexpected TransferableIdentity: " + o.getClass().getName()
                    + ". Agent moved" + sender.toAddress() + "->" + thisNodeAddress.toAddress());
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
          log.warn("TransferableIdentity does not contain private keys. "
                   + sender.toAddress() + "->" + thisNodeAddress.toAddress());
          return;
        }
        if (certificates != null) {
          if (log.isDebugEnabled()) {
            log.debug("KeySet contains " + certificates.length
                      + " certificates");
          }
        }
        else {
          log.warn("TransferableIdentity does not contain certificates. "
                   + sender.toAddress() + "->" + thisNodeAddress.toAddress());
          return;
        }
        /*
         * It should be ok to have a different number of private keys and public keys.
         */
        if (certificates.length != privateKeys.length) {
          log.warn("Operation not supported yet. Number of certificates and private keys should match.");
          return;
        }
        /* Step 2 */
        if (log.isDebugEnabled()) {
          log.debug("Installing keys of " + requestorAddress.toAddress() + " to local certificate keystore");
        }
        for (int i = 0 ; i < certificates.length ; i++) {
          keyRing.setKeyEntry(privateKeys[i], certificates[i]);
        }

        /* Step 3 */
        if (log.isDebugEnabled()) {
          log.debug("updating wp");
        }
        keyRing.updateNS(requestorAddress.toAddress());
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
          
    public void invalidate(String cname) {}
  }

}
