/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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

package org.cougaar.core.security.policy.enforcers.util;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class UserDatabase
{
  private static HashMap userToRoles = new HashMap();
  static {
    userToRoles.put(anybody(), new HashSet());
  }
  private static String  userPrefix  = "----User";
  private static int     userCounter = 0;


  /**
   * The user in no roles.
   * 
   * This is a bit of a dangerous function.  Its use depends strongly on 
   * the assumption that policies involving users and servlets are
   * all positive policies.  Thus a user cannot be denied access to a
   * servlet because he is in a certain role.  
   * 
   * Thus if the user anybody() is allowed access to a servlet then
   * anybody (with any roles) is allowed access to the servlet.  This
   * is needed because we have to determine if a user is allowed to
   * access a servlet in the case where we know nothing about the user.
   */
  public static String anybody()
  {                             
    return userPrefix + "Everybody";         
  }

  public static synchronized String login(Set roles)
  {
    String user = userPrefix + (userCounter++);
    userToRoles.put(user, roles);
    return user;
  }

  public static synchronized boolean isUser(String name)
  {
    return name.startsWith(userPrefix);
  }

  public static synchronized boolean logout(String user)
  {
    if (userToRoles.remove(user) != null) {
      return true;
    } else {
      return false;
    }
  }

  public static synchronized Set getRoles(String user)
  {
    Set roles = (Set) userToRoles.get(user);
    if (roles == null) {
      return new HashSet();
    } else {
      return roles;
    }
  }
}
