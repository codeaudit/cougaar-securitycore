/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
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
 */

package org.cougaar.core.security.auth.role;

import org.cougaar.core.security.auth.*;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.StringTokenizer;
import java.util.NoSuchElementException;

public abstract class RolePermission extends Permission {
  private String   _userRole;
  private String   _componentRole;
  private String   _agentRole;

  public RolePermission(String name, String roles) {
    super(name);

    try {
      StringTokenizer tok = new StringTokenizer(roles, ",");
      _agentRole = tok.nextToken().trim();
      _componentRole = tok.nextToken().trim();
      _userRole = tok.nextToken().trim();
    } catch (NoSuchElementException e) {
      throw new IllegalArgumentException("Bad roles list. Must be 3 comma-separated values");
    }

    if ("*".equals(_userRole)) {
      _userRole = null;
    }
    if ("*".equals(_componentRole)) {
      _componentRole = null;
    }
    if ("*".equals(_agentRole)) {
      _agentRole = null;
    }
  }

  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }

    if (!(obj instanceof RolePermission)) {
      return false;
    }

    RolePermission perm = (RolePermission) obj;

    return (eq(getName(), perm.getName()) &&
            eq(_userRole, perm._userRole) &&
            eq(_componentRole, perm._componentRole) &&
            eq(_agentRole, perm._agentRole));
  }

  public String getActions() {
    return _agentRole + "," + _componentRole + "," + _userRole;
  }
  
  public int hashCode() {
    return toString().hashCode();
  }

  public boolean implies(Permission p) {
    if (!(p instanceof RolePermission)) {
      return false;
    }

    RolePermission rp = (RolePermission) p;
    String name = getName();
    return ((name == null || name.equals(rp.getName())) &&
            (_agentRole == null || _agentRole.equals(rp._agentRole)) &&
            (_componentRole == null || 
             _componentRole.equals(rp._componentRole)) &&
            (_userRole == null || _userRole.equals(rp._userRole)));
  }

  private static boolean eq(String s1, String s2) {
    if (s1 == null) {
      return (s2 == null);
    }
    return s1.equals(s2);
  }
}
