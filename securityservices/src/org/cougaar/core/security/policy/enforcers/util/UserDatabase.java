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
