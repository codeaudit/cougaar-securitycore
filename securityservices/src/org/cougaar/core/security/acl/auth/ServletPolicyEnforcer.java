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
import java.util.List;
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
import org.cougaar.core.security.policy.ServletPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;

public class ServletPolicyEnforcer implements ServletPolicyService {

  ServiceBroker _serviceBroker;
  ServletGuard  _servletGuard;

  Context           _context = null;
  DualAuthenticator _daValve = null;

  HashMap             _authConstraints;
  HashMap             _starAuthConstraints;
  SecurityConstraint  _constraints[];
  HashSet             _roles;
  long                _sleepTime = 1000;

  public ServletPolicyEnforcer(ServiceBroker sb) {
    _serviceBroker = sb;
    _servletGuard  = new ServletGuard();
  }

  public synchronized void setContext(Context context) {
    _context = context;
    if (_constraints != null) {
      for (int i = 0; i < _constraints.length; i++) {
        _context.addConstraint(_constraints[i]);
      }
    }
    if (_roles != null) {
      Iterator iter = _roles.iterator();
      while (iter.hasNext()) {
        String role = iter.next().toString();
        _context.addSecurityRole(role);
      }
    }
  }

  public synchronized void setDualAuthenticator(DualAuthenticator da) {
    _daValve = da;
    _daValve.setAuthConstraints(_authConstraints, _starAuthConstraints);
  }
  
  public synchronized void setAuthConstraints(HashMap constraints, 
                                              HashMap starConstraints) {
    if (_daValve == null) {
      _authConstraints = constraints;
      _starAuthConstraints = starConstraints;
    } else {
      _daValve.setAuthConstraints(constraints, starConstraints);
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
    SecurityConstraint scs[];
    if (_context == null) {
      scs = _constraints;
    } else {
      scs = _context.findConstraints();
    }
    for (int i = 0; i < scs.length; i++) {
      if (scs[i].included(path, "GET")) {
        String r[] = scs[i].findAuthRoles();
        for (int j = 0; j < r.length; j++) {
          roles.add(r[j]);
        }
      }
    }
    return (String[]) roles.toArray(new String[roles.size()]);
  }

  public void setSecurityConstraints(List constraints, HashSet roles) {
    if (_context == null) {
      _constraints = (SecurityConstraint[]) 
        constraints.toArray(new SecurityConstraint[constraints.size()]);
      _roles = roles;
    } else {
      SecurityConstraint scArray[] = _context.findConstraints();
      
      // add the new constraints
      Iterator iter = constraints.iterator();
      while (iter.hasNext()) {
        SecurityConstraint constraint = (SecurityConstraint) iter.next();
        _context.addConstraint(constraint);
      }
      
      // remove the old constraints
      if (scArray != null) {
        for (int i = 0 ; i < scArray.length; i++) {
          _context.removeConstraint(scArray[i]);
        }
      }

      // first get a list of roles that currently exist:
      String oldRoles[] = _context.findSecurityRoles();
      for (int i = 0; i < oldRoles.length; i++) {
        if (roles.contains(oldRoles[i])) {
          roles.remove(oldRoles[i]); // don't need to add it
        } else {
          _context.removeSecurityRole(oldRoles[i]); // don't need it any more
        }
      }
      iter = roles.iterator();
      while (iter.hasNext()) {
        String role = iter.next().toString();
        _context.addSecurityRole(role);
      }
    }
  }

  private class ServletGuard 
    extends GuardRegistration
    implements NodeEnforcer {

    public ServletGuard() {
      super(ServletPolicy.class.getName(),
            "ServletPolicyService", _serviceBroker);
      try {
        registerEnforcer();
      } catch (Exception ex) {
        // FIXME: Shouldn't just let this drop, I think
        ex.printStackTrace();
      }
    }

    /**
     * Does nothing
     */
    public void receivePolicyMessage(Policy policyIn,
                                     String policyID,
                                     String policyName,
                                     String policyDescription,
                                     String policyScope,
                                     String policySubjectID,
                                     String policySubjectName,
                                     String policyTargetID,
                                     String policyTargetName,
                                     String policyType) {
      log.warn("This should never be called!");
    }

    /**
     * Replaces an existing policy with a new policy.
     * @param policy the new policy to be added
     */
    public void receivePolicyMessage(SecurityPolicy policyIn,
                                     String policyID,
                                     String policyName,
                                     String policyDescription,
                                     String policyScope,
                                     String policySubjectID,
                                     String policySubjectName,
                                     String policyTargetID,
                                     String policyTargetName,
                                     String policyType) {
      if (policyIn == null || !(policyIn instanceof ServletPolicy)) {
        return;
      }

      if (log.isDebugEnabled()) {
        log.debug("ServletPolicyEnforcer: Received policy message");
        log.debug(policyIn.toString());
      }

      ArrayList constraints = new ArrayList();
      ServletPolicy policy = (ServletPolicy) policyIn;
      List rules = policy.getRules();
      Iterator iter = rules.iterator();
      HashMap authConstraints = new HashMap();
      HashMap starAuthConstraints = new HashMap();
      HashSet roles = new HashSet();
      while (iter.hasNext()) {
        ServletPolicy.ServletPolicyRule rule = 
          (ServletPolicy.ServletPolicyRule) iter.next();

        SecurityConstraint constraint = new SecurityConstraint();

        if (rule.requireSSL) {
          constraint.setUserConstraint("CONFIDENTIAL");
        }

        Iterator jter = rule.roles.iterator();
        while (jter.hasNext()) {
          String role = jter.next().toString();
          constraint.addAuthRole(role);
          roles.add(role);
        }
        jter = rule.urls.iterator();
        SecurityCollection sc = new SecurityCollection(rule.agentName);
        while (jter.hasNext()) {
          String pattern = jter.next().toString();
          if (rule.agentName != null && !rule.agentName.equals("*")) {
            if (pattern.startsWith("/")) {
              pattern = "/$" + rule.agentName + pattern;
            } else {
              pattern = "/$" + rule.agentName  + "/" + pattern;
            }
          }
          sc.addPattern(pattern);

          if (rule.auth != null) {
            if ("*".equals(rule.agentName)) {
              starAuthConstraints.put(pattern,rule.auth);
            } else {
              authConstraints.put(pattern,rule.auth);
            }
          }
        }
        constraint.addCollection(sc);
        constraints.add(constraint);
      }
      setAuthConstraints(authConstraints,starAuthConstraints);
      setSecurityConstraints(constraints,roles);
    }
  }
}
