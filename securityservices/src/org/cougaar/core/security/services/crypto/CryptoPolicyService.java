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


package org.cougaar.core.security.services.crypto;

import org.cougaar.core.component.Service;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.policy.CryptoPolicy;

public interface CryptoPolicyService
  extends Service
{
  public static final int CRYPTO_POLICY_VALID       = 0;
  public static final int CRYPTO_SHOULD_SIGN        = 1;
  public static final int CRYPTO_SHOULD_ENCRYPT     = 2;
  public static final int CRYPTO_UNAVAILABLE        = 3;

  SecureMethodParam getSendPolicy(String source, String target);
  public SecureMethodParam getReceivePolicy(String source, String target);

  public int isReceivePolicyValid(String source, String target, 
                                  SecureMethodParam policy,
                                  boolean ignoreEncryption,
                                  boolean ignoreSignature);
//   public CipherSuite getSendPolicies(String source, String target);
//   public CipherSuite getReceivePolicies(String source, String target);
  /*
    public CryptoPolicy getIncomingPolicy(String target);
    public CryptoPolicy getOutgoingPolicy(String source);
  */
    public CryptoPolicy getDataProtectionPolicy(String source);
}

