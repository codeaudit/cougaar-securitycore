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


import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.log.Logger;

import java.io.IOException;
import java.io.Serializable;

import java.security.GeneralSecurityException;
import java.security.SignedObject;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.util.List;


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
   */
  public Wrapper wrap(String name, Object object) throws CertificateException, GeneralSecurityException {
    List certList = keyRingService.findCert(name, KeyRingService.LOOKUP_KEYSTORE);
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
        if (log.isWarnEnabled()) {
          log.warn(WhitePagesProtectionServiceImpl.NAME + " Object not serialable, cannot be signed");
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
   * @param wrap - the request object
   *
   * @return the object if the siganature is valid
   *
   * @throws CertificateException
   */
  public Object unwrap(String name, Wrapper wrap) throws CertificateException {
    X509Certificate[] certChain = wrap.getCertificateChain();
    for (int i = certChain.length - 1; i == 0; i--) {
      keyRingService.checkCertificateTrust(certChain[i]);
      csrv.addSSLCertificateToCache(certChain[i]);
    }

    //TODO:  add checks to make sure it is a valid bind request
    Object obj = encryptService.verify(name, policy.signSpec, wrap.getSignedObject());
    if (obj == null) {
      throw new CertificateException("request not signed with trusted agent certificate");
    }

    return obj;
  }
}
