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
import org.apache.catalina.Context;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.deploy.SecurityCollection;

// KAoS policy management
import safe.enforcer.NodeEnforcer;

// Cougaar security services
import com.nai.security.policy.GuardRegistration;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.planning.ldm.policy.RuleParameter;
import org.cougaar.core.security.services.crypto.ServletPolicyService;
import org.cougaar.core.security.provider.ServletPolicyServiceProvider;
import org.cougaar.planning.ldm.policy.KeyRuleParameterEntry;
import org.cougaar.planning.ldm.policy.KeyRuleParameter;

public class ServletPolicyEnforcer 
  extends GuardRegistration
  implements ServletPolicyService, NodeEnforcer {

  public static String AGENT_POLICY    = "agent";
  public static String NODE_POLICY     = "node";

  public static String ALLOW_ROLE      = "allow-role";
  public static String DENY_ROLE       = "deny-role";
  public static String CONSTRAINT_NAME = "auto constraint";

  private Context _context = null;

  HashMap _roles = new HashMap();

  public ServletPolicyEnforcer() {
    super("org.cougaar.core.security.policy.ServletPolicy",
          "ServletPolicyService");
    try {
      registerEnforcer();
    } catch (Exception ex) {
      // FIXME: Shouldn't just let this drop, I think
      ex.printStackTrace();
    }
  }

  public void setContext(Context context) {
    _context = context;
    ArrayList agents = new ArrayList();
    ArrayList roles  = new ArrayList();

    synchronized (_roles) {
      Iterator iter = _roles.entrySet().iterator(); 
      while (iter.hasNext()) {
        Map.Entry entry   = (Map.Entry) iter.next();
        String    agent   = (String)    entry.getKey();
        HashSet   roleSet = (HashSet)   entry.getValue();
        synchronized (roleSet) {
          Iterator rIter = roleSet.iterator();
          while (rIter.hasNext()) {
            String role = rIter.next().toString();
            agents.add(agent);
            roles.add(role);
          }
        }
      }
    }
    int len = agents.size();
    for (int i = 0; i < len; i++) {
      addRole((String)agents.get(i), (String) roles.get(i));
    }
  }

  private SecurityConstraint getSecurityConstraint(String agent) {
    SecurityConstraint sc = null;
    synchronized (_context) {
      SecurityConstraint scArray[] = _context.findConstraints();
      if (scArray != null) {
        for (int i = 0; i < scArray.length; i++) {
          if (agent.equals(scArray[i].getDisplayName())) {
            sc = scArray[i];
            break; // found it!
          }
        }
      }
      if (sc == null) {
        sc = new SecurityConstraint();
        sc.setDisplayName(agent);
        SecurityCollection scn = 
          new SecurityCollection(agent, "Agent '" + agent +
                                 "' security collection");
        scn.addPattern("/$" + agent + "/*");
        sc.addCollection(scn);
        _context.addConstraint(sc);
      }
    }
    return sc;
  }

  private HashSet getRoleSet(String agent) {
    HashSet roleList;
    synchronized (_roles) {
      roleList = (HashSet) _roles.get(agent);
      if (roleList == null) {
        roleList = new HashSet();
        _roles.put(agent,roleList);
      }
    }
    return roleList;
  }

  public void addRole(String agent, String role) {
    if (agent == null || role == null) {
      return;
    }
//     System.err.println("================================ adding role: " + agent + ", " + role);

    HashSet roleList = getRoleSet(agent);
    synchronized (roleList) {
      roleList.add(role);
    }

    if (_context != null) {
      SecurityConstraint sc = getSecurityConstraint(agent);
      sc.addAuthRole(role);
      _context.addSecurityRole(role);
    }
  }

  public void removeRole(String agent, String role) {
    if (agent == null || role == null) {
      return;
    }

    HashSet roleList = getRoleSet(agent);
    synchronized (roleList) {
      roleList.remove(role);
    }

    if (_context != null) {
      SecurityConstraint sc = getSecurityConstraint(agent);
      sc.removeAuthRole(role);
    }
  }

  public String[] getRoles(String agent) {
    SecurityConstraint sc = getSecurityConstraint(agent);

    if (sc == null) {
      return null;
    }
    return sc.findAuthRoles();
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

    if (debug) {
      System.out.println("ServletPolicyEnforcer: Received policy message");
      RuleParameter[] param = policy.getRuleParameters();
      for (int i = 0 ; i < param.length ; i++) {
        System.out.println("Rule: " + param[i].getName() +
                           " - " + param[i].getValue());
      }
    }
    // what is the policy change?
    if (AGENT_POLICY.equals(policyScope)) {
      // this is an agent-level policy change
      RuleParameter[] param = policy.getRuleParameters();
      for (int i = 0; i < param.length; i++) {
        String name  = param[i].getName();
        String value = param[i].getValue().toString();
        if (ALLOW_ROLE.equals(name)) {
          addRole(policyTargetID,value);
        } else if (DENY_ROLE.equals(name)) {
          removeRole(policyTargetID,value);
        }
      }
    } else {
      // if (NODE_POLICY.equals(policyScope)) {
      RuleParameter[] param = policy.getRuleParameters();
      for (int i = 0; i < param.length; i++) {
        if (param[i] instanceof KeyRuleParameter) {
          KeyRuleParameter krp = (KeyRuleParameter) param[i];
          String name  = krp.getName();
          KeyRuleParameterEntry entry[] = krp.getKeys();
          if (entry != null) {
            for (int j = 0; j < entry.length; j++) {
              String agent = entry[j].getKey();
              String role  = entry[j].getValue();
              if (ALLOW_ROLE.equals(name)) {
                addRole(agent,role);
              } else if (DENY_ROLE.equals(name)) {
                removeRole(agent,role);
              }
            }
          }
        }
      }
    }
  }
}
