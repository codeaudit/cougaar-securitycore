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

package org.cougaar.core.security.crypto.ldap;

import java.util.List;

import org.apache.catalina.Realm;
import org.apache.catalina.realm.GenericPrincipal;

public class CougaarPrincipal extends GenericPrincipal {
  String _loginRequirements;

  /**
   * Constructor.
   */
  public CougaarPrincipal(Realm realm, String name, 
                          List roles, String loginRequirements) {
    super(realm, name, null, roles);
    _loginRequirements = loginRequirements;
  }

  /**
   * Returns the requirements for this user to login. 
   *
   * Possible values are "CERT", "PASSWORD", "EITHER", or "BOTH".<p>
   * This class is used with DualAuthenticator and KeyRingJNDIRealm
   * in order to ensure that the user is authenticated properly.
   */
  public String getLoginRequirements() {
    return _loginRequirements;
  }

  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }

    if (!(obj instanceof CougaarPrincipal)) {
      return false;
    }

    CougaarPrincipal p = (CougaarPrincipal) obj;
    return super.equals(p) && p._loginRequirements.equals(_loginRequirements);
  }
}
