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
 * Created on September 12, 2001, 4:01 PM
 */

package org.cougaar.core.security.services.crypto;

// Cougaar core services
import org.cougaar.core.component.Service;

// Cougaar security services
import org.cougaar.core.security.crypto.SecureMethodParam;

public interface ServletPolicyService
  extends Service
{
  /**
   * returns a list of roles allowed to access the given path through
   * the servlet.
   *
   * @param path The path to search for roles.
   */
  public String[] getRoles(String path);

  /**
   * Adds an allowed role for a given path
   *
   * @param path  The path that is allowing access
   * @param role  The role name to allow
   */
  public void     addRole(String path, String role);

  /**
   * Removes access by a role to a given path added with addRole
   *
   * @param path The path to remove access from
   * @param role The role name to remove
   */
  public void     removeRole(String path, String role);
}

