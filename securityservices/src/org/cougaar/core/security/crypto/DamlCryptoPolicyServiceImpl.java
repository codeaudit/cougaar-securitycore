/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 *
 * Created on September 21, 2001, 4:17 PM
 */

package org.cougaar.core.security.crypto;

import java.util.LinkedList;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.CryptoPolicy;
import org.cougaar.core.security.policy.enforcers.ULMessageNodeEnforcer;
import org.cougaar.core.security.policy.enforcers.util.CipherSuite;
import org.cougaar.core.security.policy.enforcers.util.HardWired;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.service.LoggingService;

public class DamlCryptoPolicyServiceImpl implements CryptoPolicyService {
  private ULMessageNodeEnforcer   _enforcer;
  private LoggingService          _log;
  private CryptoPolicyServiceImpl _legacy;
  private ServiceBroker           _serviceBroker;

  public DamlCryptoPolicyServiceImpl(ServiceBroker sb) {
    _log = (LoggingService) sb.getService(this, LoggingService.class, null);
    _legacy = new CryptoPolicyServiceImpl(sb);
    _serviceBroker = sb;
  }

  private synchronized void initDaml() {
    if (_enforcer == null) {
      _enforcer = new ULMessageNodeEnforcer(_serviceBroker, new LinkedList());
      try {
        _enforcer.registerEnforcer();
      }
      catch (Exception e) {
        _enforcer = null;
        if (_log.isWarnEnabled()) {
          _log.warn("Guard not available. Running without guard");
        }
      }
    }
  }

  public SecureMethodParam getSendPolicy(String source, String target) {
    initDaml();
    return getDamlPolicy(source, target); // no direction
  }

  public SecureMethodParam getReceivePolicy(String source, String target) {
    initDaml();
    return getDamlPolicy(source, target); // no direction
  }

  public CipherSuite getSendPolicies(String source, String target) {
    if (_log.isDebugEnabled()) {
      _log.debug("Called getSendPolicies for " + source + " to " + target);
    }
    initDaml();
    //Collection c = new LinkedList();
    if (_enforcer != null) {    
      return _enforcer.getAllowedCipherSuites(source, target);
    }
    else {
      return HardWired.nsaApproved;
    }
    /*
    Iterator iter = allowed.iterator();
    while (iter.hasNext()) {
      c.add(convertPolicy((CipherSuite) iter.next()));
    }
    return c;*/
  }

  public CipherSuite getReceivePolicies(String source, String target) {
    return getSendPolicies(source, target);
  }

  public CryptoPolicy getDataProtectionPolicy(String source) {
    return _legacy.getDataProtectionPolicy(source);
  }

  public int isReceivePolicyValid(String source, String target,
                                      SecureMethodParam policy,
                                      boolean ignoreEncryption,
                                      boolean ignoreSignature) {
    if (_log.isDebugEnabled()) {
      _log.debug("Called isReceivePolicyValid for " + source +
                 " to " + target +
                 ", policy = " + policy + ", ignoreEncryption = " +
                 ignoreEncryption + ", ignoreSignature = " + ignoreSignature);
    }
    initDaml();
    CipherSuite cs = null;
    if (_enforcer != null) {
      cs = _enforcer.getAllowedCipherSuites(source, target);
    }
    else {
      cs = HardWired.nsaApproved;
    }
    if (_log.isDebugEnabled()) {
      _log.debug("Comparing against cipher suite: " + cs);
    }
    if (!cs.isCipherAvailable()) {
      return CRYPTO_UNAVAILABLE;
    }

    if (!ignoreEncryption) {
      boolean encrypt = policy.secureMethod == SecureMethodParam.ENCRYPT ||
        policy.secureMethod == SecureMethodParam.SIGNENCRYPT;
      if (encrypt) {
        if (policy.symmSpec == null ||
            policy.asymmSpec == null ||
            !cs.getSymmetric().contains(policy.symmSpec) ||
            !cs.getAsymmetric().contains(policy.asymmSpec)) {
          return CryptoPolicyServiceImpl.CRYPTO_SHOULD_ENCRYPT;
        }
      } else {
        if (!cs.getSymmetric().contains("plain")) {
          return CryptoPolicyServiceImpl.CRYPTO_SHOULD_ENCRYPT;
        }
      }
    }
    if (!ignoreSignature) {
      boolean sign = policy.secureMethod == SecureMethodParam.SIGN ||
        policy.secureMethod == SecureMethodParam.SIGNENCRYPT;

      if (sign) {
        if (policy.signSpec == null ||
            !cs.getSignature().contains(policy.signSpec)) {
          return CryptoPolicyServiceImpl.CRYPTO_SHOULD_SIGN;
        }
      } else {
        if (!cs.getSignature().contains("none")) {
          return CryptoPolicyServiceImpl.CRYPTO_SHOULD_SIGN;
        }
      }
    }
    return CryptoPolicyServiceImpl.CRYPTO_POLICY_VALID;
  }

  /**
   * Chooses the no encryption or signature if available. Otherwises
   * it chooses a semi-random cipher and signature algorithm from those
   * available.
   */ 
  public static SecureMethodParam convertPolicy(CipherSuite cs) {
    if (!cs.isCipherAvailable()) {
      return null;
    }

    SecureMethodParam policy = new SecureMethodParam();
    boolean encrypt = true;
    boolean sign = true;

    if (cs.getSymmetric().contains("plain")) {
      encrypt = false;
    }

    if (cs.getSignature().contains("none")) {
      sign = false;
    }

    if (encrypt) {
      policy.symmSpec = (String) cs.getSymmetric().iterator().next();
      policy.asymmSpec = (String) cs.getAsymmetric().iterator().next();
      if (sign) {
        policy.secureMethod = SecureMethodParam.SIGNENCRYPT;
      } else {
        policy.secureMethod = SecureMethodParam.ENCRYPT;
      }
    } else if (sign) {
      policy.secureMethod = SecureMethodParam.SIGN;
    } else {
      policy.secureMethod = SecureMethodParam.PLAIN;
    }

    if (sign) {
      policy.signSpec = (String) cs.getSignature().iterator().next();
    }

    return policy;
  }

  private SecureMethodParam getDamlPolicy(String source, String target) {
    if (_enforcer != null) {
      CipherSuite cs = _enforcer.getAllowedCipherSuites(source, target);
      return convertPolicy(cs);
    }
    else {
      return convertPolicy(HardWired.nsaApproved);
    }
  }

}  
