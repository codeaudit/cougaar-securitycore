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

import java.io.*;
import java.util.*;

import org.cougaar.core.security.policy.enforcers.ULMessageNodeEnforcer;
import org.cougaar.core.security.policy.enforcers.util.CypherSuite;
import org.cougaar.core.security.policy.enforcers.util.CypherSuiteWithAuth;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.security.policy.CryptoPolicy;
import org.cougaar.core.component.ServiceBroker;

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
      _enforcer.registerEnforcer();
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

  public Collection getSendPolicies(String source, String target) {
    if (_log.isDebugEnabled()) {
      _log.debug("Called getSendPolicies for " + source + " to " + target);
    }
    initDaml();
    Collection c = new LinkedList();
    
    Set allowed = _enforcer.getAllowedCypherSuites(source, target);
    if (allowed != null) {
      Iterator iter = allowed.iterator();
      while (iter.hasNext()) {
        c.add(convertPolicy((CypherSuite) iter.next()));
      }
    }
    return c;
  }

  public Collection getReceivePolicies(String source, String target) {
    return getSendPolicies(source, target);
  }

  public CryptoPolicy getDataProtectionPolicy(String source) {
    return _legacy.getDataProtectionPolicy(source);
  }

  private SecureMethodParam convertPolicy(CypherSuite cs) {
    SecureMethodParam policy = new SecureMethodParam();
    boolean encrypt = true;
    boolean sign = true;

    String symmetric = cs.getSymmetric();
    String hash = cs.getChecksum();

    if (symmetric == null || "plain".equals(symmetric)) {
      encrypt = false;
    }
    if (hash == null || "plain".equals(hash)) {
      sign = false;
    }
    if (encrypt) {
      if (sign) {
        policy.secureMethod = policy.SIGNENCRYPT;
      } else {
        policy.secureMethod = policy.ENCRYPT;
      }
    } else if (sign) {
      policy.secureMethod = policy.SIGN;
    } else {
      policy.secureMethod = policy.PLAIN;
    }
    policy.symmSpec = cs.getSymmetric();
    policy.asymmSpec = cs.getAsymmetric();
    policy.signSpec = cs.getChecksum() + "With" + cs.getAsymmetric();
    return policy;
  }

  private SecureMethodParam getDamlPolicy(String source, String target) {
    Set allowed = _enforcer.getAllowedCypherSuites(source, target);
    if (allowed.isEmpty()) {
      _log.warn("No valid encryption algorithm from " + source +
                " to " + target);
      return null;
    }
    // FIXME!!
    // don't know how to choose the best one, so just choose the first
    CypherSuite cs = (CypherSuite) allowed.iterator().next();
    return convertPolicy(cs);
  }

}  
