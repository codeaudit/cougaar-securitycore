/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
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
