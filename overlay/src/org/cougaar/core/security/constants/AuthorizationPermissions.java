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
package org.cougaar.core.security.constants;

import java.security.Permission;
import java.lang.reflect.Constructor;

public class AuthorizationPermissions {
  public static final Permission OPLAN_READ;
  public static final Permission OPLAN_WRITE;
  public static final Permission OPLAN_CREATE;

  private static final String AUTH_PERMISSION_CLASS =
    "org.cougaar.core.security.auth.BlackboardPermission";

  private static final String OPLAN = "oplan";
  private static final String READ  = "read";
  private static final String WRITE = "write";
  private static final String CREATE = "create";

  static {
    Permission read, write, create;
    try {
      Class permissionClass = Class.forName(AUTH_PERMISSION_CLASS);
      Class[] params = new Class[] { String.class, String.class };
      Constructor c = permissionClass.getConstructor(params);
      read  = (Permission) c.newInstance(new String[] { OPLAN, READ });
      write = (Permission) c.newInstance(new String[] { OPLAN, WRITE });
      create = (Permission) c.newInstance(new String[] { OPLAN, CREATE });
    } catch (Exception e) {
      read = null;
      write = null;
      create = null;
    }
    OPLAN_READ = read;
    OPLAN_WRITE = write;
    OPLAN_CREATE = create;
  }

}
