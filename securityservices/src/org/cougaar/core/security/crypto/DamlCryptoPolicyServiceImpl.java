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

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.CryptoPolicy;
import org.cougaar.core.security.policy.enforcers.ULMessageNodeEnforcer;
import org.cougaar.core.security.policy.enforcers.util.CipherSuite;
import org.cougaar.core.security.policy.enforcers.util.CipherSuiteMapping;
import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.service.LoggingService;

public class DamlCryptoPolicyServiceImpl implements CryptoPolicyService {
  private ULMessageNodeEnforcer   _enforcer;
  private LoggingService          _log;
  private CryptoPolicyServiceImpl _legacy;
  private ServiceBroker           _serviceBroker;
  private CipherSuite             _defaultCipherSuite;

  public DamlCryptoPolicyServiceImpl(ServiceBroker sb) 
  {
    _log = (LoggingService) sb.getService(this, LoggingService.class, null);
    _legacy = new CryptoPolicyServiceImpl(sb);
    _serviceBroker = sb;

    // The following is hacky but only applies to unguarded mode...
    Set defaultCipherNames = new HashSet();
    defaultCipherNames.add(ULOntologyNames.cipherPrefix + "NSAApprovedProtection");
    try {
      _defaultCipherSuite 
        = (new CipherSuiteMapping()).ulCiphersFromKAoSProtectionLevel(defaultCipherNames);
    } catch (IOException ioe) {
      if (_log.isDebugEnabled()) {
        _log.debug("Failed to update default cipher suite - only a problem in Guardless mode");
      }
    }
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
          _log.warn("Guard not available. Running without guard",e);
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
      cs = _defaultCipherSuite;
    }
    if (_log.isDebugEnabled()) {
      _log.debug("Comparing against cipher suite: " + cs);
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
  private static SecureMethodParam convertPolicy(CipherSuite cs) {
    if (cs.getSymmetric() == null || cs.getAsymmetric() == null) {
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
      return convertPolicy(_defaultCipherSuite);
    }
  }
}  
