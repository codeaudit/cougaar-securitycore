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
 


package org.cougaar.core.security.auth.role;

import java.security.Permission;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;

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
