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
 
 
 
 
 
 


package org.cougaar.core.security.acl.auth;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.Subject;

import org.apache.catalina.realm.GenericPrincipal;

public class UserRoles {
  /**
   * Use this function to retrieve all the user roles as inserted
   * by the SecureHookServlet
   */
  public static String[] getRoles() {
    AccessControlContext acc = AccessController.getContext();
    Subject subject = (Subject) 
      AccessController.doPrivileged(new GetSubject(acc));

    ArrayList roles = new ArrayList();
    if (subject != null) {
      Set principals = subject.getPrincipals(GenericPrincipal.class);
      Iterator i = principals.iterator();
      while (i.hasNext()) {
        GenericPrincipal principal = (GenericPrincipal) i.next();
        String proles[] = principal.getRoles();
        for (int j = 0; j < proles.length; j++) {
          roles.add(proles[j]);
        }
      }
    }
    return (String[]) roles.toArray(new String[roles.size()]);
  }

  /**
   * Use this function to retrieve all the user name as inserted
   * by the SecureHookServlet
   */
  public static String getUserName() {
    AccessControlContext acc = AccessController.getContext();
    Subject subject = (Subject) 
      AccessController.doPrivileged(new GetSubject(acc));

    //ArrayList roles = new ArrayList();
    if (subject != null) {
      Set principals = subject.getPrincipals(GenericPrincipal.class);
      Iterator i = principals.iterator();
      while (i.hasNext()) {
        GenericPrincipal principal = (GenericPrincipal) i.next();
        return principal.getName();
      }
    }
    return null;
  }

  /**
   * Use this function to retrieves the URI that the user
   * is currently accessing.
   */
  public static String getURI() {
    AccessControlContext acc = AccessController.getContext();
    Subject subject = (Subject) 
      AccessController.doPrivileged(new GetSubject(acc));

    if (subject != null) {
      Set principals = subject.getPrincipals(URIPrincipal.class);
      Iterator i = principals.iterator();
      if (i.hasNext()) {
        return ((URIPrincipal) i.next()).getURI();
      }
    }
    return null;
  }

  private static class GetSubject implements PrivilegedAction {
    AccessControlContext _acc;

    public GetSubject(AccessControlContext acc) {
      _acc = acc;
    }

    public Object run() {
      return Subject.getSubject(_acc);
    }
  }
}
