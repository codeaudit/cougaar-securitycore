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

package org.cougaar.core.security.auth.role;

import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.ObjectContext;
import org.cougaar.core.mts.MessageAddress;

import java.util.Arrays;
import java.util.List;

public class RoleExecutionContext implements ExecutionContext {
  private String[] _agentRoles;
  private String[] _componentRoles;
  private String[] _userRoles;
  private String   _component = "";
  private MessageAddress _agent;
  private String   _user      = "";

  RoleExecutionContext(MessageAddress agent, String component, String user,
                       String[] agentRoles, String[] componentRoles, 
                       String[] userRoles) {
    if (component != null) {
      _component      = component;
    }
    _agent          = agent;
    if (user != null) { 
      _user = user;
    }

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

  public MessageAddress getAgent() {
    return _agent;
  }

  public String getComponent() {
    return _component;
  }

  public boolean equals(Object o) {
    if(this == o) {
      return true;
    }
    if(o instanceof RoleExecutionContext) {
      RoleExecutionContext rc = (RoleExecutionContext)o;
      // this object's roles
      boolean agentEqual;
      if (_agent == null) {
        agentEqual = rc._agent == null;
      } else {
        agentEqual = _agent.equals(rc._agent);
      }
      return (_component.equals(rc._component) &&
              agentEqual &&
              _user.equals(rc._user) &&
              Arrays.equals(_agentRoles, rc._agentRoles) &&
              Arrays.equals(_componentRoles, rc._componentRoles) &&
              Arrays.equals(_userRoles, rc._userRoles));
    }
    return false;
  }

  public int hashCode() {
    return _agent.hashCode() ^ _component.hashCode() ^ _user.hashCode();
  }

  public String toString() {
    StringBuffer sb = new StringBuffer(256);
    sb.append(formatRoleString("agent roles", _agentRoles));
    sb.append("\n");
    sb.append(formatRoleString("component roles", _componentRoles));
    sb.append("\n");
    sb.append(formatRoleString("user roles", _userRoles));
    sb.append("\n");
    return sb.toString();
  }
  
   private String formatRoleString(String role, String []roles) {
    StringBuffer sb = new StringBuffer();
    sb.append(role + " (");
    for(int i = 0; i < roles.length; i++) {
      sb.append(roles[i]);
      if((i + 1) < roles.length) {
        sb.append(", ");
      } 
    }
    sb.append(")");
    return sb.toString();
  }

  private List normalizeArrayToList(String []arr) {
    if(arr == null) {
      return Arrays.asList(new String[0]);
    }
    return Arrays.asList(arr);
  }
}
