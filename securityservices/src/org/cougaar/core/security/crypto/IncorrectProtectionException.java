/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */


package org.cougaar.core.security.crypto;

import java.security.cert.X509Certificate;

import org.cougaar.core.security.services.crypto.CryptoPolicyService;

public class IncorrectProtectionException 
  extends Exception
  implements java.io.Serializable {

  private int _policyValidity = CryptoPolicyService.CRYPTO_POLICY_VALID;
  private X509Certificate   _cert = null;

  public IncorrectProtectionException(int policyValidity) {
    _policyValidity = policyValidity;
  }

  public IncorrectProtectionException(X509Certificate cert) {
    _cert = cert;
  }

  //  public SecureMethodParam getPolicy() {
  //    return _policy;
  //  }

  public X509Certificate getCertificate() {
    return _cert;
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

    if (_cert != null) {
      return "Private key for certificate could not be found: " +
        _cert.getSubjectDN().getName();
    }
    return "Invalid policy";
  }
}
