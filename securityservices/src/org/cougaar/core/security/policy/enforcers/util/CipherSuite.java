/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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

package org.cougaar.core.security.policy.enforcers.util;

import java.util.Set;
import java.util.HashSet;
import java.util.Collections;

/**
 * This class represents a suite of crypto algorithms including symmetric, 
 * assymmetric and checksum algorithms.  
 */


public class CipherSuite {
  private Set _symmetric;
  private Set _asymmetric;
  private Set _signature;

  /**
   * Construct a Cipher Suite.
   *
   * The arguments are vectors of strings.  Each string represents
   * an algorithm.  Thus I could use a vector containing "3DES" for
   * symmetric, etc.
   *
   */
  public CipherSuite(Set symmetric,
                     Set asymmetric,
                     Set signature) {
    _symmetric  = new HashSet();
    _asymmetric = new HashSet();
    _signature   = new HashSet();
    if (symmetric != null) {
      _symmetric.addAll(symmetric);
    }
    if (asymmetric != null) {
      _asymmetric.addAll(asymmetric);
    }
    if (signature != null) {
      _signature.addAll(signature);
    }
  }

  public CipherSuite() {
    this(null, null, null);
  }

  /**
   * returns if there are any cipher suites that are valid
   */
  public boolean isCipherAvailable() {
    return !_symmetric.isEmpty() && 
      !_signature.isEmpty() && 
      !_asymmetric.isEmpty();
  }

  /**
   * Returns the vector of symmetric algorithms in the suite as a
   * vector of strings.
   */
  public Set getSymmetric()   { return _symmetric; }
  /**
   * Returns the vector of assymmetric algorithms in the suite as a
   * vector of strings.
   */
  public Set getAsymmetric() { return _asymmetric; }
  /**
   * Returns the vector of checksum algorithms in the suite as a
   * vector of strings.
   */
  public Set getSignature()    { return _signature;   }

  public void addSymmetric(String symm) {
    _symmetric.add(symm);
  }

  public void addAsymmetric(String asymm) {
    _asymmetric.add(asymm);
  }

  public void addSignature(String sig) {
    _signature.add(sig);
  }

  public void addAll(CipherSuite cs) {
    _symmetric.addAll(cs._symmetric);
    _asymmetric.addAll(cs._asymmetric);
    _signature.addAll(cs._signature);
  }

  public String toString() {
    return "CipherSuite: symmetric = " + _symmetric + 
      ", asymmetric = " + _asymmetric + 
      ", signature = " + _signature;
  }

  public int hashCode() {
    return _symmetric.hashCode() ^
      _asymmetric.hashCode() ^
      _signature.hashCode();
  }

  public boolean equals(Object obj) {
    if (obj instanceof CipherSuite) {
      CipherSuite c = (CipherSuite) obj;
      return (c._symmetric.equals(_symmetric) &&
              c._asymmetric.equals(_asymmetric) &&
              c._signature.equals(_signature));
    }
    return false;
  }
    
}
