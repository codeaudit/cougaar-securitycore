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



package org.cougaar.core.security.crypto;

import java.io.IOException;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;

public class IncorrectProtectionException 
  extends IOException
  implements java.io.Serializable 
{

  private int _policyValidity = CryptoPolicyService.CRYPTO_POLICY_VALID;

  public IncorrectProtectionException(int policyValidity) {
    _policyValidity = policyValidity;
  }

  public int reason()
  {
    return _policyValidity;
  }

  public String getMessage() {
    if (_policyValidity == CryptoPolicyService.CRYPTO_SHOULD_SIGN) {
      return "Sender should be signing, Probable cause = new ssl credentials or policy mismatch";
    } else if (_policyValidity == CryptoPolicyService.CRYPTO_SHOULD_ENCRYPT) {
      return "Sender should be encrypting, Probable cause = policy mismatch";
    } else if (_policyValidity == CryptoPolicyService.CRYPTO_UNAVAILABLE) {
      return "Policy requires unavailable encryption scheme.";
    } else if (_policyValidity != CryptoPolicyService.CRYPTO_POLICY_VALID) {
      return "Unknown policy exception (see CryptoPolicyService.java) - " 
        + _policyValidity;
    }
    return "Invalid policy";
  }
}
