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
        log = (LoggingService) serviceBroker.getService(this,
                LoggingService.class, null);
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
     * @param request ProtectedRequest containing  requesting agent's
     *        certificate information and the  YPMessage
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
