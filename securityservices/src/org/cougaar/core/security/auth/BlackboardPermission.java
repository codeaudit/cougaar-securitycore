/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
import java.util.Set;
import java.util.StringTokenizer;

/**
 * A Java security manager permission to add, delete, change, or 
 * query the black board service.
 *
 * For example, the following permission only allows components in myfile.jar 
 * to query for only java.lang objects from the blackboard.
 *
 * grant codeBase "file:${org.cougaar.install.path}${/}sys${/}myfile.jar" signedBy "privileged" {
 *  ....
 *  permission org.cougaar.core.security.auth.BlackboardPermission "java.lang.*", "query";
 *  ....
 * };
 *
 */
public final class BlackboardPermission extends ServicePermission {
  private final static String[] ACTIONS = {
    "add", "change", "query", "remove"
  };

  /**
   * A blackboard permission to add, change, remove, and/or query for a particular 
   * object or package.
   *
   * @param name the class or package name (for example java.lang.String or java.lang.*)
   * @param actions add, change, remove, and/or query (* for all actions)
   */
  public BlackboardPermission(String name, String actions) {
    super(name, actions);
  }

  protected String[] getAvailableActions() {
    return ACTIONS;
  }

  protected Set nameableObjects()
  {
    return org.cougaar.core.security.auth.role.
      AuthServiceImpl.nameableBlackboardObjects();
  }

}
