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

