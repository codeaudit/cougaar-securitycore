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
import javax.security.auth.Subject;

import org.apache.catalina.realm.GenericPrincipal;

public class UserRoles {
  private static final String[] STRING_ARRAY = new String[1];

  private static PrivilegedAction _default = new UserRolesImpl();

  /**
   * Use this function to retrieve all the user roles as inserted
   * by the SecureHookServlet
   */
  public static String[] getRoles() {
    return (String[]) AccessController.doPrivileged(_default,
                                                    AccessController.getContext());
  }

  private static class UserRolesImpl implements PrivilegedAction {
    public UserRolesImpl() {
    }

    public Object run() {
      AccessControlContext context = AccessController.getContext();
      Subject mySubject = Subject.getSubject(context);
      
      ArrayList roles = new ArrayList();
      if (mySubject != null) {
        Set principals = mySubject.getPrincipals();
        Iterator i = principals.iterator();
        while (i.hasNext()) {
          Object principal = i.next();
          if (principal instanceof GenericPrincipal) {
            String proles[] = ((GenericPrincipal) principal).getRoles();
            for (int j = 0; j < proles.length; j++) {
              roles.add(proles[j]);
            }
          }
        }
      }
      return roles.toArray(STRING_ARRAY);
    }
  }
}
