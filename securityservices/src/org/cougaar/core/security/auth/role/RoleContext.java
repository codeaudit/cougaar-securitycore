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

package org.cougaar.core.security.auth.role;

import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.ObjectContext;

import java.util.Arrays;

public class RoleContext implements ExecutionContext, ObjectContext {
  private String[] _agentRoles;
  private String[] _componentRoles;
  private String[] _userRoles;

  RoleContext(String[] agentRoles, String[] componentRoles, 
              String[] userRoles) {
    _agentRoles     = agentRoles;
    _componentRoles = componentRoles;
    _userRoles      = userRoles;

    if (_agentRoles != null) {
      Arrays.sort(_agentRoles);
    }
    if (_componentRoles != null) {
      Arrays.sort(_componentRoles);
    }
    if (_userRoles != null) {
      Arrays.sort(_userRoles);
    }
  }

  public boolean hasAgentRole(String role) { 
    if (_agentRoles == null) {
      return false;
    }
    
    return (Arrays.binarySearch(_agentRoles, role) > 0); 
  }
  public boolean hasComponentRole(String role) { 
    if (_componentRoles == null) {
      return false;
    }
    return (Arrays.binarySearch(_componentRoles, role) > 0); 
  }
  public boolean hasUserRole(String role) { 
    if (_userRoles == null) {
      return false;
    }
    return (Arrays.binarySearch(_userRoles, role) > 0); 
  }
}
