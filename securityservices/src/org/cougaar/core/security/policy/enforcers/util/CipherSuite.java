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


package org.cougaar.core.security.policy.enforcers.util;

import java.util.HashSet;
import java.util.Set;

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
