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


package org.cougaar.core.security.dataprotection;

import java.security.cert.X509Certificate;

import org.cougaar.core.security.crypto.ProtectedObject;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.policy.PersistenceManagerPolicy;

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
  private PersistenceManagerPolicy _policy;

  public DataProtectionKeyImpl(byte[] secretKey,
			       String digestAlg,
			       SecureMethodParam policy,
			       X509Certificate[] certChain) {
    super(policy, secretKey);
    digestAlgSpec = digestAlg;
    certificateChain = certChain;
  }

  public DataProtectionKeyImpl(byte[] secretKey,
			       String digestAlg,
			       SecureMethodParam policy,
			       X509Certificate[] certChain,
                               PersistenceManagerPolicy pmp) {
    this(secretKey, digestAlg, policy, certChain);
    _policy = pmp;
  }

  public PersistenceManagerPolicy getPMPolicy() {
    return _policy;
  }

  public boolean equals(DataProtectionKeyImpl key) {
    //if (!getObject().toString().equals(key.getObject().toString()))
    //  return false;
    X509Certificate [] certChain = key.getCertificateChain();
    if (certificateChain.length == 0 || certChain.length == 0)
      return false;
    return certificateChain[0].equals(certChain[0]);
  }

  public int hashCode() {
    return super.hashCode();
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
