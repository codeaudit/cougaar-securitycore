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
 */

package org.cougaar.core.security.auth;

import java.security.Permission;

import org.cougaar.core.security.services.auth.AuthorizationService;
import org.cougaar.core.security.services.auth.SecurityContextService;

public class ObjectContextUtil {
  private static SecurityContextService _scs;
  private static AuthorizationService   _auth;

  public static Permission SET_CONTEXT_PERMISSION = 
    new ContextPermission("setContextService");
  public static Permission SET_AUTH_PERMISSION = 
    new ContextPermission("setAuthorizationService");

  public static void setContextService(SecurityContextService scs) {
    SecurityManager sm = System.getSecurityManager();
    if (sm != null) {
      sm.checkPermission(SET_CONTEXT_PERMISSION);
    }
    _scs = scs;
  }

  public static void setAuthorizationService(AuthorizationService auth) {
    SecurityManager sm = System.getSecurityManager();
    if (sm != null) {
      sm.checkPermission(SET_AUTH_PERMISSION);
    }
    _auth = auth;
  }
  
  public static ObjectContext createContext(Object obj) {
    if (_scs == null || _auth == null) {
      return null;
    }
    ExecutionContext ctx = _scs.getExecutionContext();
    if (ctx == null) {
      return null;
    }
    return _auth.createObjectContext(ctx, obj);
  }
}
