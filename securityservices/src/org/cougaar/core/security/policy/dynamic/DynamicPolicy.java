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


package org.cougaar.core.security.policy.dynamic;

import java.security.AccessController;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.security.SecurityPermission;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.cougaar.core.security.auth.ServicePermission;
import org.cougaar.core.security.services.auth.AuthorizationService;

public class DynamicPolicy extends Policy {
  private Policy       _basePolicy;
  private AuthorizationService _auth;

  public DynamicPolicy(Policy base, AuthorizationService daml) {
    _basePolicy = base;
    _auth = daml;
  }

  public static void install(AuthorizationService daml) {
    AccessController.doPrivileged( new SetPolicy(daml) );
  }

  public PermissionCollection getPermissions(CodeSource codeSource) {
    return _basePolicy.getPermissions(codeSource);
  }

  public PermissionCollection getPermissions(ProtectionDomain domain) {
    if (_auth != null) {
      return new DynamicPermissionCollection(domain);
    }
    return _basePolicy.getPermissions(domain);
  }

  public boolean implies(ProtectionDomain domain, Permission permission) {
    if (permission instanceof ServicePermission) {
      PermissionCollection coll = getPermissions(domain);
      return coll.implies(permission);
    }
    return _basePolicy.implies(domain, permission);
  }

  public void refresh() {
    _basePolicy.refresh();
  }
  
  public void setAuthorizationService(AuthorizationService daml) {
    SecurityManager sm = System.getSecurityManager();
    if (sm != null) {
      sm.checkPermission(new SecurityPermission("setPolicy"));
    }
    _auth = daml;
  }

  /*
  private static boolean isServicePermission(Permission perm) {
    // I don't trust the class loader to be the same as the Permission's
    // so I won't use instanceof
    Class clz = perm.getClass();
    while (clz != null) {
      if (clz.getName().equals("org.cougaar.core.security." +
                               "auth.ServicePermission")) {
        return true;
      }
      clz = clz.getSuperclass();
    }
    return false;
  }
  */

  private class DynamicPermissionCollection extends PermissionCollection {
    private ProtectionDomain     _domain;
    private List                 _damlPolicies;
    private Vector               _policies; // use Vector for Enumeration

    public DynamicPermissionCollection(ProtectionDomain domain) {
      _domain = domain;
    }

    public void add(Permission permission) {
      throw new SecurityException("You must modify policies using DAML");
    }

    public synchronized Enumeration elements() {
      if (_policies == null) {
        _damlPolicies = _auth.getPermissions(_domain);
        _policies = new Vector(_damlPolicies);
        Enumeration enum = 
          _basePolicy.getPermissions(_domain).elements();
        while (enum.hasMoreElements()) {
          _policies.add(enum.nextElement());
        }
      }

      return _policies.elements();
    }

    public boolean isReadOnly() {
      return true;
    }

    public void setReadOnly() {
      // already read-only
    }

    public String toString() {
      return "DynamicPermissionCollection(" + _domain + ")";
    }

    public synchronized boolean implies(Permission permission) {
      if (permission instanceof ServicePermission) {
        if (_damlPolicies != null) {
          Iterator iter = _damlPolicies.iterator();
          while (iter.hasNext()) {
            Permission p = (Permission) iter.next();
            if (p.implies(permission)) {
              return true;
            }
          }
          return false; // not in the list
        }
        return _auth.implies(_domain, permission);
      }
      return _basePolicy.implies(_domain, permission);
    }
  } // end of DynamicPermissionCollection

  private static class SetPolicy implements PrivilegedAction {
    private AuthorizationService _auth;
    public SetPolicy(AuthorizationService daml) {
      _auth = daml;
    }

    public Object run() {
      Policy p = Policy.getPolicy();
      if (!(p instanceof DynamicPolicy)) {
        p = new DynamicPolicy(p, _auth);
        Policy.setPolicy(p);
      }
      return null;
    }
  }
}
