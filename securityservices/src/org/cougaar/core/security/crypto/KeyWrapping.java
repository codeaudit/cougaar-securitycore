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
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;

import java.lang.IllegalArgumentException;

// Cougaar core infrastructure
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;


// Cougaar security services
import org.cougaar.core.security.util.CryptoDebug;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

// Cougaar Overlay
import org.cougaar.core.service.identity.TransferableIdentity;

public class KeyWrapping
{
  private EncryptionService encryptionService;
  private ServiceBroker serviceBroker;
  private LoggingService log;

  public KeyWrapping(ServiceBroker sb)
  {
    // TODO: use service broker
    encryptionService = null;

    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
  }

  /** @param privKey        The private keys to wrap
   *  @param cert           The certificates to wrap
   *  @param signerPrivKey  The private key of the signer
   *  @param signerCert     The certificate of the signer
   *  @param rcvrCert       The certificate of the intended receiver
   */
  public TransferableIdentity protectPrivateKey(PrivateKey[] privKey,
						X509Certificate[] cert,
						PrivateKey signerPrivKey,
						X509Certificate signerCert,
						X509Certificate rcvrCert)
  {
    if (log.isDebugEnabled()) {
      log.debug("Wrapping keys");
    }

    KeyIdentity keyIdentity = null;

    KeySet keySet = new KeySet(privKey, cert);
    MessageAddress sourceAgent = null;
    MessageAddress targetAgent = null;
    SecureMethodParam policy = null;
    try {
      encryptionService.protectObject(keySet,
				      sourceAgent, targetAgent,
				      policy);
    }
    catch (GeneralSecurityException e) {
    }
    catch (IOException e) {
    }
    return keyIdentity;
  }

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private key of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  public TransferableIdentity getPfx(byte[] pfxBytes,
				     PrivateKey rcvrPrivKey,
				     Certificate rcvrCert)
  {
    KeyIdentity keyIdentity = null;
    return keyIdentity;
  }
}
