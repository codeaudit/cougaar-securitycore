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

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * This class represents a suite of crypto algorithms including symmetric, 
 * assymmetric and checksum algorithms.  
 */


public class CipherSuite {
  private String _name;
  private Set _symmetric;
  private Set _asymmetric;
  private Set _signature;
  private Map _conditionMap;

  public final static int PROTECTED_LAN = 1;

  /**
   * Construct a Cipher Suite.
   *
   * The arguments are vectors of strings.  Each string represents
   * an algorithm.  Thus I could use a vector containing "3DES" for
   * symmetric, etc.
   *
   */
  public CipherSuite(String name) {
    _name         = name;
    init();
  }


  public CipherSuite() {
    _name = null;
    init();
  }

  private void init()
  {
    _symmetric    = new LinkedHashSet();
    _asymmetric   = new LinkedHashSet();
    _signature    = new LinkedHashSet();
    _conditionMap = new HashMap();
  }

  /**
   * Returns the vector of symmetric algorithms in the suite as a
   * vector of strings.
   */
  public Set getSymmetric()   { return _symmetric; }


  /**
   * Returns the vector of symmetric algorithms in the suite as a
   * vector of strings based on network environment such as protected lan or
   * vpn connection
   */
  public Set getSymmetric(int condition)   
  { 
    Object o = _conditionMap.get(new Integer(condition));
    if (o == null) {
      return _symmetric;
    } else {
      return ((CipherSuite) o)._symmetric;
    }
  }


  public void addSymmetric(String symm) {
    _symmetric.add(symm);
  }

  public void addSymmetric(int condition, String symm) {
    CipherSuite cs = getConditionalCipherSuite(condition);
    cs._symmetric.add(symm);
  }


  /**
   * Returns the vector of assymmetric algorithms in the suite as a
   * vector of strings.
   */
  public Set getAsymmetric() { return _asymmetric; }

  /**
   * Returns the vector of assymmetric algorithms in the suite as a
   * vector of strings based on network environment such as protected lan or
   * vpn connection
   */
  public Set getAsymmetric(int condition) 
  { 
    Object o = _conditionMap.get(new Integer(condition));
    if (o == null) {
      return _asymmetric;
    } else {
      return ((CipherSuite) o)._asymmetric;
    }
  }

  public void addAsymmetric(String asymm) {
    _asymmetric.add(asymm);
  }

  public void addAsymmetric(int condition, String asymm) 
  {
    CipherSuite cs = getConditionalCipherSuite(condition);
    cs._asymmetric.add(asymm);
  }

  /**
   * Returns the vector of checksum algorithms in the suite as a
   * vector of strings.
   */
  public Set getSignature()    { return _signature;   }


  /**
   * Returns the vector of signature algorithms in the suite as a
   * vector of strings based on network environment such as protected lan or
   * vpn connection
   */
  public Set getSignature(int condition) 
  { 
    Object o = _conditionMap.get(new Integer(condition));
    if (o == null) {
      return _signature;
    } else {
      return ((CipherSuite) o)._signature;
    }
  }


  public void addSignature(String sig) {
    _signature.add(sig);
  }

  public void addSignature(int condition, String sig) {
    CipherSuite cs = getConditionalCipherSuite(condition);
    cs._signature.add(sig);
  }


  public void addAll(CipherSuite cs)
  {
    _symmetric.addAll(cs._symmetric);
    _asymmetric.addAll(cs._asymmetric);
    _signature.addAll(cs._signature);
    for (Iterator conditions = cs._conditionMap.keySet().iterator(); 
         conditions.hasNext();) {
      Integer conditionType = (Integer) conditions.next();
      CipherSuite mycs = getConditionalCipherSuite(conditionType.intValue());
      CipherSuite othercs = (CipherSuite) cs._conditionMap.get(conditionType);
      mycs._symmetric.addAll(othercs._symmetric);
      mycs._asymmetric.addAll(othercs._asymmetric);
      mycs._signature.addAll(othercs._signature);
    }
  }

  private CipherSuite getConditionalCipherSuite(int condition)
  {
    Integer cond = new Integer(condition);
    Object o = _conditionMap.get(cond);
    if (o == null) {
      CipherSuite cs = new CipherSuite();
      _conditionMap.put(cond, (Object) cs);
      return cs;
    } else {
      return (CipherSuite) o;
    }
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
