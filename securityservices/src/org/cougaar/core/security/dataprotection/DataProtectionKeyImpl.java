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

package org.cougaar.core.security.dataprotection;

import org.cougaar.core.security.crypto.ProtectedObject;
import org.cougaar.core.security.crypto.SecureMethodParam;

import java.security.cert.X509Certificate;

import javax.crypto.SealedObject;

/**
 * This key is to be put into storage by client.
 * It can be stored in plain text because all its important variables
 *  are protected.
 * - SecretKey is the actual secret key asymmEncrypt with agent key
 */
public class DataProtectionKeyImpl
  extends ProtectedObject
{
  private String digestAlgSpec;

  /** The certificate chain of the entity that was used to encrypt the secret key. */
  private X509Certificate[] certificateChain;

  private X509Certificate oldSigner;

  public DataProtectionKeyImpl(byte[] secretKey,
			       String digestAlg,
			       SecureMethodParam policy,
			       X509Certificate[] certChain) {
    super(policy, secretKey);
    digestAlgSpec = digestAlg;
    certificateChain = certChain;
  }

  public boolean equals(DataProtectionKeyImpl key) {
    //if (!getObject().toString().equals(key.getObject().toString()))
    //  return false;
    X509Certificate [] certChain = key.getCertificateChain();
    if (certificateChain.length == 0 || certChain.length == 0)
      return false;
    return certificateChain[0].equals(certChain[0]);
  }

  public String getDigestAlg() {
    return digestAlgSpec;
  }

  /** Get the certificate chain of the entity that was used to encrypt the secret key. */
  public X509Certificate[] getCertificateChain() {
    return certificateChain;
  }

  public X509Certificate getOldSigner() {
    return oldSigner;
  }

  public void setOldSigner(X509Certificate signer) {
    oldSigner = signer;
  }
}
