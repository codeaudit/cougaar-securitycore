package org.cougaar.core.security.policy.enforcers.util;

import java.util.Set;

/**
 * This class represents a suite of crypto algorithms including symmetric, 
 * assymmetric and checksum algorithms.  
 */


public class CypherSuite {
  private String _symmetric;
  private String _assymetric;
  private String  _checksum;

  /**
   * Construct a Cypher Suite.
   *
   * The arguments are vectors of strings.  Each string represents
   * an algorithm.  Thus I could use a vector containing "3DES" for
   * symmetric, etc.
   *
   */
  public CypherSuite(String symmetric,
                     String assymetric,
                     String checksum) {
    _symmetric  = symmetric;
    _assymetric = assymetric;
    _checksum   = checksum;
  }

  /**
   * Returns the vector of symmetric algorithms in the suite as a
   * vector of strings.
   */
  public String getSymmetric()   { return _symmetric;  }
  /**
   * Returns the vector of assymmetric algorithms in the suite as a
   * vector of strings.
   */
  public String getAssymmetric() { return _assymetric; }
  /**
   * Returns the vector of checksum algorithms in the suite as a
   * vector of strings.
   */
  public String getChecksum()    { return _checksum;   }

  public String toString() {
    return "CypherSuite: symmetric = " + _symmetric + 
      ", asymmetric = " + _assymetric + 
      ", checksum = " + _checksum;
  }

  public int hashCode() {
    int hash = 0;
    if (_symmetric != null) {
      hash = _symmetric.hashCode();
    }
    if (_assymetric != null) {
      hash ^= _assymetric.hashCode();
    }
    if (_checksum != null) {
      hash ^= _checksum.hashCode();
    }
    return hash;
  }

  public boolean equals(Object obj) {
    if (obj instanceof CypherSuite) {
      CypherSuite c = (CypherSuite) obj;
      return (eq(c._symmetric, _symmetric) &&
              eq(c._assymetric, _assymetric) &&
              eq(c._checksum, _checksum));
    }
    return false;
  }
    
  private static boolean eq(String one, String two) {
    if (one == null || two == null) {
      return one == two;
    }
    return one.equals(two);
  }
}
