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


package org.cougaar.core.security.services.wp;


import java.io.IOException;
import java.io.Serializable;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.SignedObject;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.NoValidKeyException;
import org.cougaar.core.security.crypto.PrivateKeyCert;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.wp.WhitePagesProtectionService;
import org.cougaar.util.log.Logger;

import sun.security.x509.X500Name;


/**
 * Implementation of the <code>WhitePagesProtectionService</code>
 *
 * @author mabrams
 *
 * @see org.cougaar.core.security.services.wp.WhitePagesProtectionService
 */
public class WhitePagesProtectionServiceImpl implements WhitePagesProtectionService {
  private static final String NAME = "WhitePagesProtectionServiceImpl";
  private ServiceBroker serviceBroker = null;
  private Logger log = null;
  private EncryptionService encryptService = null;
  private CertificateCacheService csrv = null;
  private KeyRingService keyRingService = null;
  private SecureMethodParam policy = null;

  /**
   * Creates a new WhitePagesProtectionServiceImpl object.
   *
   * @param sb the <code>ServiceBroker</code>
   */
  public WhitePagesProtectionServiceImpl(ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService) serviceBroker.getService(this, LoggingService.class, null);
    encryptService = (EncryptionService) serviceBroker.getService(this, EncryptionService.class, null);
    csrv = (CertificateCacheService) serviceBroker.getService(this, CertificateCacheService.class, null);
    keyRingService = (KeyRingService) serviceBroker.getService(this, KeyRingService.class, null);
    policy = new SecureMethodParam();
    if (log.isDebugEnabled()) {
      log.debug(WhitePagesProtectionServiceImpl.NAME + " instantiated");
    }
  }

  /**
   * Signs the request and wraps the request with the certificate chain used
   * for signing
   *
   * @param name - The agent making the request
   * @param object - the request object (should implement Serializable)
   *
   * @return the wraped request object
   *
   * @throws CertificateException
   * @throws GeneralSecurityException
   * @throws RuntimeException DOCUMENT ME!
   */
  public Wrapper wrap(String name, Object object) throws CertificateException, GeneralSecurityException {
    if (log.isDebugEnabled()) {
      log.debug(WhitePagesProtectionServiceImpl.NAME + " wrapping object: " + object + " (class: " + object.getClass().getName() + ") with name + " + name);
    }

    keyRingService = (KeyRingService) serviceBroker.getService(this, KeyRingService.class, null);

    if (keyRingService == null) {
      throw new RuntimeException("KeyRingService is null");
    }

    encryptService = (EncryptionService) serviceBroker.getService(this, EncryptionService.class, null);

    if (encryptService == null) {
      throw new RuntimeException("EncryptionService is null");
    }


//    List certList = keyRingService.findCert(name, KeyRingService.LOOKUP_KEYSTORE);
	List certList = new ArrayList();
	try {
		List pkeyList = getPrivateKeys(name, keyRingService);
                if (pkeyList != null) {
                  for (int i = 0; i < pkeyList.size(); i++) {
                    PrivateKeyCert pkey = (PrivateKeyCert)pkeyList.get(i);
                    certList.add(pkey.getCertificateStatus());
                  }
                }
	} catch (GeneralSecurityException e1) {
		throw (e1);
	} catch (IOException e1) {
		throw (new GeneralSecurityException(e1.getMessage()));
	}
	
	if ((certList == null) || !(certList.size() > 0)) {
      throw new CertificateException("No certificate available for encrypting or signing: " + name);
    }


    CertificateStatus cs = (CertificateStatus) certList.get(0);
    X509Certificate agentCert = (X509Certificate) cs.getCertificate();
    X509Certificate[] certChain = keyRingService.buildCertificateChain(agentCert);

    SignedObject signedObj = null;

    try {
      Serializable serializableObject;
      if (object instanceof Serializable) {
        serializableObject = (Serializable) object;
        signedObj = encryptService.sign(name, policy.signSpec, serializableObject);
      } else {
        if (log.isErrorEnabled()) {
          log.error(WhitePagesProtectionServiceImpl.NAME + " Object not serializable, cannot be signed");
        }
      }
    } catch (GeneralSecurityException e) {
      throw new GeneralSecurityException(WhitePagesProtectionServiceImpl.NAME + " " + e.getMessage());
    } catch (IOException e) {
      if (log.isWarnEnabled()) {
        log.warn(WhitePagesProtectionServiceImpl.NAME + " IOException: " + e);
      }

      throw new GeneralSecurityException(WhitePagesProtectionServiceImpl.NAME + " " + e.getMessage());
    }
    	
    return new ProtectedRequest(certChain, signedObj);
  }


  /**
   * Installs and verifies the signing certificate
   *
   * @param name - The agent making the request
   * @param wrapper - the request object
   *
   * @return the object if the siganature is valid
   *
   * @throws CertificateException
   * @throws RuntimeException DOCUMENT ME!
   */
  public Object unwrap(String name, Wrapper wrapper) throws CertificateException {
    ProtectedRequest wrap = (ProtectedRequest) wrapper;
    if (log.isDebugEnabled()) {
      log.debug(WhitePagesProtectionServiceImpl.NAME + " unwrapping object: " + wrap.getSignedObject() + " with name + " + name);
    }

    keyRingService = (KeyRingService) serviceBroker.getService(this, KeyRingService.class, null);

    if (keyRingService == null) {
      throw new RuntimeException("KeyRingService is null");
    }

    encryptService = (EncryptionService) serviceBroker.getService(this, EncryptionService.class, null);

    if (encryptService == null) {
      throw new RuntimeException("EncryptionService is null");
    }

    csrv = (CertificateCacheService) serviceBroker.getService(this, CertificateCacheService.class, null);

    if (encryptService == null) {
      throw new RuntimeException("CertificateCacheService is null");
    }

    X509Certificate[] certChain = wrap.getCertificateChain();
	
	for (int i = 0; i < certChain.length; i++) {		
      keyRingService.checkCertificateTrust(certChain[i]);
      csrv.addSSLCertificateToCache(certChain[i]);
    }

    Object obj = encryptService.verify(name, policy.signSpec, wrap.getSignedObject());
    if (obj == null) {
      throw new CertificateException("request not signed with trusted agent certificate");
    }

    return obj;
  }
  
  private List getPrivateKeys(final String name, final KeyRingService keyRing)
	 throws GeneralSecurityException, IOException {
	 List pkList = (List)
	   AccessController.doPrivileged(new PrivilegedAction() {
		   public Object run(){
			 // relieve messages to naming, for local keys
			 // do not need to go to naming
			 List nameList = keyRing.getX500NameFromNameMapping(name);
			 //List nameList = keyRing.findDNFromNS(name);
			 if (log.isDebugEnabled()) {
			   log.debug("List of names for " + name + ": " + nameList);
			 }
			 List keyList = new ArrayList();
			 for (int i = 0; i < nameList.size(); i++) {
			   X500Name dname = (X500Name)nameList.get(i);
			   List pkCerts = keyRing.findPrivateKey(dname);
			   if (pkCerts == null) {
				 return keyList;
			   }
                           keyList.addAll(pkCerts);
			 }
			 return keyList;
		   }
		 });
	 if (pkList == null || pkList.size() == 0) {
	   String message = "Unable to get private key of " +
		 name + " -- does not exist.";
	   if (log.isWarnEnabled()) {
		 log.warn(message);
	   }
	   throw new NoValidKeyException(message);
	 }
	 return pkList;
   }

}
