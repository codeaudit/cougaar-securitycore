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
 


package org.cougaar.core.security.auth.role;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.auth.ExecutionContext;

public class RoleExecutionContext implements ExecutionContext {
  public static final String ACCESS_CACHING_PROPERTY = 
    "org.cougaar.core.security.policy.auth.role.useAccessCaching";
  private static final boolean ALLOW_ACCESS_CACHING
    = Boolean.getBoolean(ACCESS_CACHING_PROPERTY);

  private String[] _agentRoles;
  private String[] _componentRoles;
  private String[] _userRoles;
  private String   _component = "";
  private MessageAddress _agent;
  private String   _user      = "";
  private Map _descriptors;
  private int _policyUpdateCounter = 0;

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
    _descriptors = new HashMap();
  }

  public boolean hasAgentRole(String role) { 
    if (_agentRoles == null) {
      return false; 
    }
    
    return (Arrays.binarySearch(_agentRoles, role) >= 0); 
  }

  public boolean hasComponentRole(String role) { 
    if (_componentRoles == null) {
      return false;
    }
    return (Arrays.binarySearch(_componentRoles, role) >= 0); 
  }

  public boolean hasUserRole(String role) { 
    if (_userRoles == null) {
      return false;
    }
    return (Arrays.binarySearch(_userRoles, role) >= 0); 
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
    sb.append("component (" + _component + ")\n");
    sb.append("agent (" + _agent + ")\n");
    sb.append("user (" + _user + ")\n");
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

  public void flushAuthorizationCache()
  {
    _descriptors = new HashMap();
  }

  public boolean cachedIsAuthorized(String objectName,
                                    String access[],
                                    int policyUpdateCounter)
  {
    if (!ALLOW_ACCESS_CACHING) {
      return false;
    }

    if (policyUpdateCounter != _policyUpdateCounter) {
      flushAuthorizationCache();
      _policyUpdateCounter = policyUpdateCounter;
      return false;
    }
    Set accessModes = (Set) _descriptors.get(objectName);
    if (accessModes == null) {
      return false;
    } else {
      for (int i = 0; i < access.length; i++) {
        if (! accessModes.contains(access[i])) {
          return false;
        }
      }
      return true;
    }
  }

  /* package */ void updateCachedAuthorization(String objectName,
                                               String access [],
                                               int policyUpdateCounter)
  {
    if (!ALLOW_ACCESS_CACHING) {
      return;
    }
    if (policyUpdateCounter != _policyUpdateCounter) {
      flushAuthorizationCache();
    }

    Set accessModes = (Set) _descriptors.get(objectName);
    if (accessModes == null) {
      accessModes = new HashSet();
    }
    for (int i = 0; i < access.length; i++) {
      accessModes.add(access[i]);
    }
    _descriptors.put(objectName, accessModes);
  }
  

  /*
  private List normalizeArrayToList(String []arr) {
    if(arr == null) {
      return Arrays.asList(new String[0]);
    }
    return Arrays.asList(arr);
  }
  */
}
