/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
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
 */
package org.cougaar.core.security.auth;

import java.security.Permission;
import java.lang.reflect.Method;

public class AuthorizationUtil {
  private static Method CREATE_CONTEXT;

  private static synchronized void initContextCall() {
    if (CREATE_CONTEXT == null) {
      try {
        Class c = Class.forName("org.cougaar.core.security.auth.ObjectContextUtil");
        CREATE_CONTEXT = c.getMethod("createContext", 
                                     new Class[] {Object.class} );
      } catch (Exception e) {
        // FIXME!! remove stack trace dump
        e.printStackTrace();
        // not available. That means that security services isn't installed
      }
    }
  }

  static {
    initContextCall();
  }

  public static Object createObjectContext(Object o) {
    if (CREATE_CONTEXT == null) {
      initContextCall();
    }
    if (CREATE_CONTEXT != null) {
      try {
        return CREATE_CONTEXT.invoke(null, new Object[] {o});
      } catch (Exception e) {
        e.printStackTrace(); // should not get here
        return null;
      }
    }
    return null;
  }

  public static void checkPermission(Permission p, Object obj) {
    if (obj != null) {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null && p != null) {
        sm.checkPermission(p, obj);
      }
    }
  }
}
