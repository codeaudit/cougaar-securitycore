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
 *
 * Created on September 12, 2001, 10:55 AM
 */

package org.cougaar.core.security.acl.auth;

import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

// Tomcat 4.0 security constraints
import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.deploy.SecurityCollection;

// KAoS policy management
import safe.enforcer.NodeEnforcer;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.planning.ldm.policy.RuleParameter;
import org.cougaar.planning.ldm.policy.KeyRuleParameterEntry;
import org.cougaar.planning.ldm.policy.KeyRuleParameter;
import org.cougaar.planning.ldm.policy.LongRuleParameter;

// Cougaar security services
import org.cougaar.core.security.policy.GuardRegistration;
import org.cougaar.core.security.services.crypto.ServletPolicyService;
import org.cougaar.core.security.provider.ServletPolicyServiceProvider;
import org.cougaar.core.security.acl.auth.DualAuthenticator;

public class ServletPolicyEnforcer 
  extends GuardRegistration
  implements ServletPolicyService, NodeEnforcer {

  public  static final String ALLOW_ROLE            = "allow-role";
  public  static final String DENY_ROLE             = "deny-role";
  public  static final String SET_AUTH_CONSTRAINT   = "auth-constraint";
  public  static final String SET_LOGIN_FAILURE_SLEEP_TIME = "login-failure-sleep";

  private static final String STR_ARRAY[]           = new String[1];

  private Context           _context = null;
  private DualAuthenticator _daValve = null;

  HashMap _roles       = new HashMap();
  HashMap _constraints = new HashMap();
  long    _sleepTime   = 1000;

  public ServletPolicyEnforcer(ServiceBroker sb) {
    super("org.cougaar.core.security.policy.ServletPolicy",
          "ServletPolicyService", sb);
    try {
      registerEnforcer();
    } catch (Exception ex) {
      // FIXME: Shouldn't just let this drop, I think
      ex.printStackTrace();
    }
  }

  public synchronized void setContext(Context context) {
    _context = context;
    Iterator iter = _roles.entrySet().iterator(); 
    while (iter.hasNext()) {
      Map.Entry entry   = (Map.Entry) iter.next();
      String    path    = (String)    entry.getKey();
      HashSet   roleSet = (HashSet)   entry.getValue();
      iter.remove();
      SecurityConstraint sc = getSecurityConstraint(path);
      _context.addConstraint(sc);
      Iterator rIter = roleSet.iterator();
      while (rIter.hasNext()) {
        String role = rIter.next().toString();
        sc.addAuthRole(role);
      }
    }
  }

  public synchronized void setDualAuthenticator(DualAuthenticator da) {
    _daValve = da;
    Iterator iter = _constraints.entrySet().iterator(); 
    while (iter.hasNext()) {
      Map.Entry entry      = (Map.Entry) iter.next();
      String    path       = (String) entry.getKey();
      String    constraint = (String) entry.getValue();
      iter.remove();
      _daValve.setAuthConstraint(path,constraint);
    }
    _daValve.setLoginFailureSleepTime(_sleepTime);
  }
  
  private SecurityConstraint getSecurityConstraint(String path) {
    SecurityConstraint sc = null;

    SecurityConstraint scArray[] = _context.findConstraints();
    if (scArray != null) {
      for (int i = 0; i < scArray.length; i++) {
        if (path.equals(scArray[i].getDisplayName())) {
          sc = scArray[i];
          break; // found it!
        }
      }
      }
    if (sc == null) {
      sc = new SecurityConstraint();
      sc.setDisplayName(path);
      SecurityCollection scn = 
        new SecurityCollection(path, "Security constraint for path: " + 
                               path);
      scn.addPattern(path);
      sc.addCollection(scn);
      _context.addConstraint(sc);
    }
    return sc;
  }

  private HashSet getRoleSet(String path) {
    HashSet roleList;
    roleList = (HashSet) _roles.get(path);
    if (roleList == null) {
      roleList = new HashSet();
      _roles.put(path,roleList);
    }
    return roleList;
  }

  public synchronized void addRole(String path, String role) {
    if (path == null || role == null) {
      return;
    }
//     System.err.println("================================ adding role: " + path + ", " + role);

    if (_context == null) {
      HashSet roleList = getRoleSet(path);
      if (_context == null) {
        roleList.add(role);
      }
    } 
    if (_context != null) {
      SecurityConstraint sc = getSecurityConstraint(path);
      sc.addAuthRole(role);
      _context.addSecurityRole(role);
    }
  }

  public synchronized void removeRole(String path, String role) {
    if (path == null || role == null) {
      return;
    }
    
    if (_context == null) {
      HashSet roleList = getRoleSet(path);
      roleList.remove(role);
    } else {
      SecurityConstraint sc = getSecurityConstraint(path);
      sc.removeAuthRole(role);
    }
  }

  public synchronized void setAuthConstraint(String path, String type) {
    if (path == null || type == null) {
      return;
    }
//     System.err.println("================================ adding constraint: " + path + ", " + type);

    if (_daValve == null) {
      _constraints.put(path, type);
    } else {
      _daValve.setAuthConstraint(path, type);
    }
  }

  public synchronized void setLoginSleepTime(long sleepTime) {
    if (_daValve == null) {
      _sleepTime = sleepTime;
    } else {
      _daValve.setLoginFailureSleepTime(sleepTime);
    }
  }

  public synchronized String[] getRoles(String path) {
    HashSet roles = new HashSet();
    if (_context == null) {
      Iterator iter = _constraints.entrySet().iterator();
      while (iter.hasNext()) {
        Map.Entry entry = (Map.Entry) iter.next();
        String wildPath = (String)entry.getKey();
        boolean match;
        if (wildPath.startsWith("*")) {
          match = path.endsWith(wildPath.substring(1));
        } else if (wildPath.endsWith("*")) {
          match = path.startsWith(wildPath.substring(0,wildPath.length()-1));
        } else {
          match = path.equals(wildPath);
        }
        if (match) {
          HashSet r = (HashSet) entry.getValue();
          Iterator rIter = r.iterator();
          while (rIter.hasNext()) {
            roles.add(rIter.next());
          }
        }
      }
    } else {
      SecurityConstraint scs[] = _context.findConstraints();
      for (int i = 0; i < scs.length; i++) {
        if (scs[i].included(path, "GET")) {
          String r[] = scs[i].findAuthRoles();
          for (int j = 0; j < r.length; j++) {
            roles.add(r[j]);
          }
        }
      }
    }
    return (String[]) roles.toArray(STR_ARRAY);
  }

  /**
   * Merges an existing policy with a new policy.
   * @param policy the new policy to be added
   */
  public void receivePolicyMessage(Policy policy,
                                   String policyID,
                                   String policyName,
                                   String policyDescription,
                                   String policyScope,
                                   String policySubjectID,
                                   String policySubjectName,
                                   String policyTargetID,
                                   String policyTargetName,
                                   String policyType) {
//     System.err.println("========================== got a role");
    if (policy == null) {
      return;
    }

    if (log.isDebugEnabled()) {
      log.debug("ServletPolicyEnforcer: Received policy message");
      RuleParameter[] param = policy.getRuleParameters();
      for (int i = 0 ; i < param.length ; i++) {
        log.debug("Rule: " + param[i].getName() +
                           " - " + param[i].getValue());
      }
    }
    // what is the policy change?
    RuleParameter[] param = policy.getRuleParameters();
    for (int i = 0; i < param.length; i++) {
      String name  = param[i].getName();
      if (param[i] instanceof LongRuleParameter) {
        if (SET_LOGIN_FAILURE_SLEEP_TIME.equals(name)) {
          _sleepTime = (((Long)param[i].getValue()).longValue());
        }
      } else if (param[i] instanceof KeyRuleParameter) {
        KeyRuleParameter krp = (KeyRuleParameter) param[i];
        KeyRuleParameterEntry entry[] = krp.getKeys();
        String agent = name;
        name = krp.getValue().toString();
        if (entry != null) {
          for (int j = 0; j < entry.length; j++) {
            String val = entry[j].getValue();
            String path = entry[j].getKey();
            if (agent != null && agent.length() != 0) {
              if (path.startsWith("/")) {
                path = "/$" + agent + path;
              } else {
                path = "/$" + agent + "/" + path;
              }
            }

            if (ALLOW_ROLE.equals(name)) {
              addRole(path,val);
            } else if (DENY_ROLE.equals(name)) {
              removeRole(path,val);
            } else if (SET_AUTH_CONSTRAINT.equals(name)) {
              setAuthConstraint(path,val);
            } 
          }
        }
      }
    }
  }
}
