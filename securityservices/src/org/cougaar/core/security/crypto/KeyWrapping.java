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

// Cougaar security services
import org.cougaar.core.security.util.CryptoDebug;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.services.identity.TransferableIdentity;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

public class KeyWrapping
{
  private EncryptionService encryptionService;

  public KeyWrapping()
  {
    // TODO: use service broker
    encryptionService = null;
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
    if (CryptoDebug.debug) {
      System.out.println("Wrapping keys");
    }

    KeyIdentity keyIdentity = null;

    KeySet keySet = new KeySet(privKey, cert);
    String sourceAgent = null;
    String targetAgent = null;
    SecureMethodParam policy = null;

    encryptionService.signAndEncrypt(keySet,
				     sourceAgent, targetAgent,
				     policy);
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
