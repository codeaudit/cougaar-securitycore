/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 *
 * Created on September 12, 2001, 10:55 AM
 */

package org.cougaar.core.security.acl.auth;

import java.util.ArrayList;
import java.util.Set;
import java.util.Iterator;
import java.security.AccessController;
import java.security.AccessControlContext;
import java.security.PrivilegedAction;
import java.security.DomainCombiner;
import javax.security.auth.Subject;
import javax.security.auth.SubjectDomainCombiner;

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
