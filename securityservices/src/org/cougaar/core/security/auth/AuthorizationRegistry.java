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

package org.cougaar.core.security.auth;

import java.util.WeakHashMap;

public class AuthorizationRegistry {
  private static WeakHashMap _scMap = new WeakHashMap();
  public static ExecutionContext getExecutionContext() {
    synchronized (_scMap) {
      return (ExecutionContext) _scMap.get(Thread.currentThread());
    }
  }

  public static ObjectContext    getObjectContext(Object obj) { 
    if (obj instanceof SecuredObject) {
      return ((SecuredObject) obj).getObjectContext();
    }
    return null;
  }

  public static void setExecutionContext(Thread thread, 
                                         ExecutionContext context) {
    SecurityManager sm = System.getSecurityManager();

    if (sm != null) {
      sm.checkPermission(new AuthRegistryPermission("setExecutionContext"));
    }

    synchronized(_scMap) {
      _scMap.put(thread, context);
    }
  }
}
