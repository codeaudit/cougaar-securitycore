/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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


package org.cougaar.core.security.dataprotection.plugin;


import sun.security.x509.X500Name;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import javax.security.auth.x500.X500Principal;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.dataprotection.DataProtectionKeyCollection;
import org.cougaar.core.security.dataprotection.DataProtectionKeyImpl;
import org.cougaar.core.security.dataprotection.DataProtectionKeyUnlockRequest;
import org.cougaar.core.security.dataprotection.DataProtectionRequestContent;
import org.cougaar.core.security.dataprotection.DataProtectionStatus;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DataProtectionKey;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import java.security.cert.X509Certificate;

import java.util.Collection;
import java.util.Iterator;


/**
 * DOCUMENT ME!
 *
 * @author $author$
 * @version $Revision: 1.9 $
 */
public class KeyRecoveryRequestHandler implements BlackboardClient {
  private ServiceBroker serviceBroker;
  private KeyRingService keyRing;
  private EncryptionService encryptionService;
  private LoggingService log;
  private MessageAddress persistenceAgentAddress;
  private BlackboardService bbs;

  /**
   * Creates a new KeyRecoveryRequestHandler object.
   *
   * @param sb DOCUMENT ME!
   * @param address DOCUMENT ME!
   */
  public KeyRecoveryRequestHandler(ServiceBroker sb, MessageAddress address) {
    serviceBroker = sb;
    persistenceAgentAddress = address;

    log = (LoggingService) serviceBroker.getService(this, LoggingService.class, null);

    // Get encryption service
    encryptionService = (EncryptionService) serviceBroker.getService(this, EncryptionService.class, null);
    // Get keyring service
    keyRing = (KeyRingService) serviceBroker.getService(this, KeyRingService.class, null);
    //Get Blackboard service
    bbs = (BlackboardService) serviceBroker.getService(this, BlackboardService.class, null);
  }

  private UnaryPredicate dataProtectionPredicate(final DataProtectionKeyImpl dpKey) {
    return new UnaryPredicate() {
        public boolean execute(Object o) {
        	if(o instanceof DataProtectionKeyContainer){
        		DataProtectionKeyContainer container = (DataProtectionKeyContainer)o;
        		if(log.isDebugEnabled()){
        			try{
        			log.debug("Check dpkey, remote copy:" + dpKey.getCertificateChain()[0].getSignature());
        			log.debug("Check dpkey, local copy:" + container.getKey().getCertificateChain()[0].getSignature());
        			}catch(NullPointerException npe){
        				log.debug("Null dpkey cert");
        				
        			}
        		}
        		return container.getKey().equals(dpKey);
        	}
          return false;
        }
      };
  }


  /**
   * DOCUMENT ME!
   *
   * @param request DOCUMENT ME!
   */
  public void processKeyRecoveryRequest(DataProtectionKeyUnlockRequest request) {
    if (request == null) {
      if (log.isWarnEnabled()) {
        log.warn("A request is null");
      }

      return;
    }

    DataProtectionRequestContent content = (DataProtectionRequestContent) request.getContent();
    if (content == null) {
      if (log.isWarnEnabled()) {
        log.warn("A request has no content");
      }

      return;
    }


    // First, verify that the X.500 name of the new agent's key matches
    // the X.500 name of the orginal certificate.
    DataProtectionKeyCollection keyCollection = content.getKeyCollection();
    if ((keyCollection == null) || (keyCollection.size() == 0)) {
      if (log.isWarnEnabled()) {
        log.warn("A request contains no key collection");
      }

      return;
    }

    DataProtectionKeyImpl keyImpl = (DataProtectionKeyImpl) keyCollection.get(0);

    //TODO Is this in the right place 
    //check if exists on blackboard, if not return b/c invalid snap shot

    bbs.openTransaction();
    
    Collection dpKeyCollection = bbs.query(dataProtectionPredicate(keyImpl));
    bbs.closeTransaction();
    if (dpKeyCollection.size() == 0) {
      if (log.isWarnEnabled()) {
        log.warn("A request dataprotection key was not on the persistence manager blackboard, must be compromised snapshot");
      }
      
      return;
    }

    X509Certificate[] originalCertChain = keyImpl.getCertificateChain();
    if ((originalCertChain == null) || (originalCertChain.length == 0)) {
      if (log.isWarnEnabled()) {
        log.warn("A request contains no certificate chain for the original agent");
      }

      return;
    }

    X509Certificate originalAgentCert = originalCertChain[0];

    // Verify the trust of the certificate.
    try {
      keyRing.checkCertificateTrust(originalAgentCert);
    } catch (Exception e) {
      if (log.isWarnEnabled()) {
        log.warn("A request contains an untrusted certificate (from original agent):" + e);
      }

      return;
    }

    X500Principal originalX500Principal = originalAgentCert.getSubjectX500Principal();
    if (originalX500Principal == null) {
      if (log.isWarnEnabled()) {
        log.warn("A request contains no X.500 name for the original agent");
      }

      return;
    }


    //
    // Now get the certificate chain of the new agent.
    X509Certificate[] newCertChain = content.getRequestorCertificateChain();
    if ((newCertChain == null) || (newCertChain.length == 0)) {
      if (log.isWarnEnabled()) {
        log.warn("A request contains no certificate chain for the new agent");
      }

      return;
    }

    X509Certificate newAgentCert = newCertChain[0];

    // Verify the trust of the certificate.
    try {
      keyRing.checkCertificateTrust(newAgentCert);
    } catch (Exception e) {
      if (log.isWarnEnabled()) {
        log.warn("A request contains an untrusted certificate (from new agent):" + e);
      }

      return;
    }

    X500Principal newX500Principal = newAgentCert.getSubjectX500Principal();
    if (newX500Principal == null) {
      if (log.isWarnEnabled()) {
        log.warn("A request contains no X.500 name for the new agent");
      }

      return;
    }


    // Compare the names
    // Cannot assume that the same CA is signing the new cert
    // with the same cert attribute policy

    /*
       if (!originalX500Principal.equals(newX500Principal)) {
         if (log.isWarnEnabled()) {
       log.warn("A request is invalid. X.500 names do not match. Original name:"
          + originalX500Principal.toString() +
          " - New name: " + newX500Principal.toString());
           }
           return;
         }
     */

    // Second, try to retrieve the secret key.
    Iterator it = keyCollection.iterator();
    if (it.hasNext()) {
      // Skip the first one, we know it cannot be encrypted using our key
      // (because it is always encrypted using the original agent's key).
      it.next();
    }

    SecretKey skey = null;
    SecureMethodParam policy = null;
    DataProtectionKeyImpl dpKey = null;

    while (it.hasNext()) {
      dpKey = (DataProtectionKeyImpl) it.next();
      try {
        policy = dpKey.getSecureMethod();
        skey = (SecretKey) encryptionService.asymmDecrypt(persistenceAgentAddress.toAddress(), policy.asymmSpec, (SealedObject) dpKey.getObject());
        break;
      } catch (Exception e) {
        if (log.isInfoEnabled()) {
          log.info("Wrong key. Trying next");
        }
      }
    }

    if (skey == null) {
      if (log.isWarnEnabled()) {
        log.warn("The private key cannot be recovered");
      }

      return;
    }

    // Third, re-encrypt the data protection key with the new agent's key.
    String newAgentName = null;
    try {
      X500Name agentx500 = new X500Name(newAgentCert.getSubjectX500Principal().getName());
      newAgentName = agentx500.getCommonName();
    } catch (Exception iox) {
      if (log.isWarnEnabled()) {
        log.warn("Cannot get agent common name: " + newAgentCert);
      }

      return;
    }

    SealedObject skeyobj = null;
    try {
      skeyobj = encryptionService.asymmEncrypt(newAgentName, policy.asymmSpec, skey, newAgentCert);
    } catch (Exception e) {
      if (log.isWarnEnabled()) {
        log.warn("The private key cannot be re-encrypted");
      }

      return;
    }

    DataProtectionKeyImpl reEncryptedKey = new DataProtectionKeyImpl(skeyobj, dpKey.getDigestAlg(), policy, newCertChain);
    request.updateResponse(request.getSource(), reEncryptedKey);

    DataProtectionStatus.addInputStatus(newAgentName, DataProtectionStatus.KEY_RECOVERED);
  }


  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardClient#getBlackboardClientName()
   */
  public String getBlackboardClientName() {
    return this.getClass().getName();
  }


  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardClient#currentTimeMillis()
   */
  public long currentTimeMillis() {
    return System.currentTimeMillis();
  }
}
