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



/*
 * Created on Jul 28, 2003
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package org.cougaar.core.security.services.yp;


import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.wp.ProtectedRequest;
import org.cougaar.core.service.LoggingService;
import org.cougaar.yp.YPMessage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SignedObject;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;


/**
 * Implementation of the YellowPagesProtectionService.
 *
 * @author ttschampel
 */
public class YellowPagesProtectionServiceImpl
  implements YellowPagesProtectionService {
  private static final String NAME = "YellowPagesProtectionServiceImpl";
  private ServiceBroker serviceBroker = null;
  private LoggingService log = null;
  private EncryptionService encryptService = null;
  private CertificateCacheService csrv = null;
  private KeyRingService keyRingService = null;
  private SecureMethodParam policy = null;

  /**
   * Creates a new YellowPagesProtectionServiceImpl object.
   *
   * @param sb ServiceBroker
   */
  public YellowPagesProtectionServiceImpl(ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService) serviceBroker.getService(this, LoggingService.class,
        null);
    encryptService = (EncryptionService) serviceBroker.getService(this,
        EncryptionService.class, null);
    csrv = (CertificateCacheService) serviceBroker.getService(this,
        CertificateCacheService.class, null);
    keyRingService = (KeyRingService) serviceBroker.getService(this,
        KeyRingService.class, null);
    policy = new SecureMethodParam();
    if (log.isDebugEnabled()) {
      log.debug(NAME + " instantiated");
    }
  }

  /**
   * Create a ProtectedRequest for a YPMessage
   *
   * @param agent Name of the requesting Agent
   * @param message The Yellow Pages Message
   *
   * @return ProtectedRequest
   *
   * @throws CertificateException CertificationException
   * @throws GeneralSecurityException GeneralSecurityException
   */
  public ProtectedRequest protectMessage(String agent, YPMessage message)
    throws CertificateException, GeneralSecurityException {
    List certList = keyRingService.findCert(agent,
        KeyRingService.LOOKUP_KEYSTORE);
    if ((certList == null) || !(certList.size() > 0)) {
      throw new CertificateException(
        "No certificate available for encrypting or signing: " + agent);
    }

    CertificateStatus cs = (CertificateStatus) certList.get(0);
    X509Certificate agentCert = (X509Certificate) cs.getCertificate();
    X509Certificate[] certChain = keyRingService.buildCertificateChain(agentCert);


    SignedObject signedObj = null;

    try {
      signedObj = encryptService.sign(agent, policy.signSpec, message);
    } catch (GeneralSecurityException e) {
      throw new GeneralSecurityException(NAME + " " + e.getMessage());
    } catch (IOException e) {
      if (log.isWarnEnabled()) {
        log.warn(NAME + " IOException: " + e);
      }

      throw new GeneralSecurityException(NAME + " " + e.getMessage());
    }

    return new ProtectedRequest(certChain, signedObj);
  }


  /**
   * Verify the Yellow Page Message is valid
   *
   * @param agent requesting agent
   * @param request ProtectedRequest containing  requesting agent's certificate
   *        information and the  YPMessage
   *
   * @throws CertificateException Exception when invalid YPMessage sent
   */
  public void verfifyMessage(String agent, ProtectedRequest request)
    throws CertificateException {
    X509Certificate[] certChain = request.getCertificateChain();
    for (int i = certChain.length - 1; i == 0; i--) {
      keyRingService.checkCertificateTrust(certChain[i]);
      csrv.addSSLCertificateToCache(certChain[i]);
    }

    Object signedObj = encryptService.verify(agent, policy.signSpec,
        request.getSignedObject());
    if (signedObj == null) {
      throw new CertificateException(
        "message not signed with trusted agent certificate");
    }
  }
}
