package org.cougaar.core.security.policy.enforcers.util;

import org.cougaar.core.security.policy.enforcers.util.CipherSuite;

import java.util.*;

/**
 * This class extends the CipherSuite class to include an
 * authentication method.  A distinction that this class has over its
 * superclass is that it always represents a single set of cipher algorithms.
 *
 * This class also exports some public constants representing how the
 * user authenticates himself (e.g. password, certificate or nothing).
 */

public class AuthSuite
{
  public final static int authCertificate = 4;
  public final static int authPassword    = 2;
  public final static int authNoAuth      = 1;
  public final static int authInvalid     = 0;
  
  private int _auth = authInvalid;
  private Set _sslSuites = new HashSet();


  public AuthSuite(Set sslSuites, int auth) {
    _auth = auth;
    if (sslSuites != null) {
      _sslSuites.addAll(sslSuites);
    }
  }

  public AuthSuite() {}

  public int getAuth() { return _auth; }
  
  public void setAuth(int auth) { _auth = auth; }

  public Set getSSL() { return _sslSuites; }
  
  public void addSSL(String cipher) { _sslSuites.add(cipher); }

  public boolean contains(String cipher, int auth) {
    return _sslSuites.contains(cipher) && ((_auth & auth) == auth);
  }

  public void addAll(AuthSuite cwa) {
    _auth |= cwa._auth;
    _sslSuites.addAll(cwa._sslSuites);
  }

  public String toString() {
    return "AuthSuite auth = " + _auth + ", ssl ciphers = " + _sslSuites;
  }

  public int hashCode() {
    return _auth ^ _sslSuites.hashCode();
  }

  public boolean equals(Object obj) {
    if (obj instanceof AuthSuite) {
      AuthSuite c = (AuthSuite) obj;
      return _auth == c._auth && _sslSuites.equals(c._sslSuites);
    }
    return false;
  }
}

