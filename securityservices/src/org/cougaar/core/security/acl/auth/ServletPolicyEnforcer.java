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

package org.cougaar.core.security.acl.auth;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Manager;
import org.apache.catalina.Session;
import org.apache.catalina.deploy.SecurityCollection;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.session.StandardManager;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.GuardRegistration;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.policy.ServletPolicy;
import org.cougaar.core.security.services.crypto.ServletPolicyService;
import org.cougaar.planning.ldm.policy.Policy;

import safe.enforcer.NodeEnforcer;

public class ServletPolicyEnforcer 
  implements ServletPolicyService/*, PropertyChangeListener*/ {

  private ServiceBroker _serviceBroker;
  private ServletGuard  _servletGuard;

  private Context           _context = null;
  private DualAuthenticator _daValve = null;

  private HashMap             _authConstraints;
  private HashMap             _starAuthConstraints;
  private SecurityConstraint  _constraints[];
  private HashSet             _roles;
  private long                _sleepTime = 1000;
  private long                _sessionLife;
  private HashSet             _agents = new HashSet();
  private static final boolean USE_DAML = 
    Boolean.getBoolean(DualAuthenticator.DAML_PROPERTY);

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
    synchronized (_agents) {
      Iterator iter = _agents.iterator();
      while (iter.hasNext()) {
        String agent = (String) iter.next();
        addStarAgent(agent);
      } // end of while (iter.hasNext())
    }
    
//     _context.addPropertyChangeListener(this);
  }

  /*  
  public void propertyChange(PropertyChangeEvent evt) {
    String name = evt.getPropertyName();
    if (name.equals("manager")) {
      _context.removePropertyChangeListener(this);
      _context.setManager(new LimitSessionManager((Manager)evt.getNewValue()));
    } // end of if (name.equals("manager"))
  }
  */

  public synchronized void setDualAuthenticator(DualAuthenticator da) {
    if (!USE_DAML) {
      _daValve = da;
      _daValve.setAuthConstraints(_authConstraints, _starAuthConstraints);
      _daValve.setLoginFailureSleepTime(_sleepTime);
      _daValve.setSessionLife(_sessionLife);
    }
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

  public synchronized void setSessionLife(long sessionLife) {
    _sessionLife = sessionLife;
    if (_daValve != null) {
      _daValve.setSessionLife(sessionLife);
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

      // add the constraints for agents currently on the node
      synchronized (_agents) {
        iter = _agents.iterator();
        while (iter.hasNext()) {
          addStarAgent((String) iter.next());
        }
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
	if (oldRoles[i] != null) {
	  if (roles.contains(oldRoles[i])) {
	    roles.remove(oldRoles[i]); // don't need to add it
	  } else {
	    _context.removeSecurityRole(oldRoles[i]); // don't need it any more
	  }
	}
      }
      iter = roles.iterator();
      while (iter.hasNext()) {
        String role = iter.next().toString();
        _context.addSecurityRole(role);
      }
    }
  }

  public void addAgent(String agentName) {
    synchronized (_agents) {
      if (_agents.contains(agentName)) {
        return; // already there
      }
      _agents.add(agentName);
      if (_context != null) {
        addStarAgent(agentName);
      } // end of if (_context != null)
    }
  }

  private void addStarAgent(String agentName) {
    SecurityConstraint scs[] = _context.findConstraints();
    if (scs == null) {
      return; // no constraints! 
    }

    for (int i = 0; i < scs.length; i++) {
      SecurityCollection starColl = scs[i].findCollection("*");
      if (starColl == null) {
        continue; // no "*" constraints here
      }

      // copy the constraint
      SecurityConstraint scNew = new SecurityConstraint();
      String roles[] = scs[i].findAuthRoles();
      for (int j = 0; j < roles.length; j++) {
        scNew.addAuthRole(roles[j]);
      }
          
      SecurityCollection scnNew = new SecurityCollection(agentName);
      String patterns[] = starColl.findPatterns();
      for (int j = 0; j < patterns.length; j++) {
        if (patterns[j].startsWith("/")) {
          scnNew.addPattern("/$" + agentName + patterns[j]);
        } else {
          scnNew.addPattern("/$" + agentName + "/" + patterns[j]);
        }
      }
      scNew.addCollection(scnNew);
      _context.addConstraint(scNew);
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
        if (log.isWarnEnabled()) {
          log.warn("Guard not available. Running without policy");
        }
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
      if (USE_DAML) {
        if(log.isInfoEnabled()) {
          log.info("Ignoring XML Servlet Policy -- using DAML");
        }
        return;
      }
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

      setLoginSleepTime(policy.getFailureDelay());
      setSessionLife(policy.getSessionLife());
      while (iter.hasNext()) {
        ServletPolicy.ServletPolicyRule rule = 
          (ServletPolicy.ServletPolicyRule) iter.next();

        SecurityConstraint constraint = new SecurityConstraint();

        if (rule.requireSSL) {
          constraint.setUserConstraint("CONFIDENTIAL");
        }

        Iterator jter = rule.roles.iterator();
        boolean hasStar = false;
        while (jter.hasNext()) {
          String role = jter.next().toString();
          if ("*".equals(role)) {
            hasStar = true;
          }
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

          if (rule.auth != null && !hasStar) {
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

  public class LimitSessionManager implements Manager {
    Manager _mgr;

    public LimitSessionManager(Manager mgr) {
      if (mgr != null) {
        _mgr = mgr;
      } else {
        _mgr = new StandardManager();
      }
    }

    public boolean getDistributable(){
      return _mgr.getDistributable();
    }

    public void setDistributable(boolean distributable){
      _mgr.setDistributable(distributable);
    }

    public String getInfo(){
      return _mgr.getInfo();
    }

    public void load() 
      throws ClassNotFoundException, java.io.IOException {
      _mgr.load();
    }

    public void unload() throws java.io.IOException {
      _mgr.unload();
    }

    public int getMaxInactiveInterval(){
      return _mgr.getMaxInactiveInterval();
    }

    public void setMaxInactiveInterval(int interval){
      _mgr.setMaxInactiveInterval(interval);
    }

    public void add(Session session){
      _mgr.add(session);
    }

    public void addPropertyChangeListener(java.beans.PropertyChangeListener listener){
      _mgr.addPropertyChangeListener(listener);
    }

    public Session createSession(){
      return _mgr.createSession();
    }

    public Session findSession(String id)
      throws java.io.IOException{
      Session session = _mgr.findSession(id);
      if (session != null) {
        if (System.currentTimeMillis() - 
            session.getCreationTime() > _sessionLife) {
          session.expire();
          session = null;
        } 
      } 
      return session;
    }

    public Session[] findSessions(){
      Session[] sessions = _mgr.findSessions();
      for (int i = 0; i < sessions.length; i++) {
        if (System.currentTimeMillis() - 
            sessions[i].getCreationTime() > _sessionLife) {
        sessions[i].expire();
        }
      } // end of for (int i = 0; i < sessions.length; i++)
      return sessions;
    }

    public void remove(Session session){
      _mgr.remove(session);
    }

    public void removePropertyChangeListener(java.beans.PropertyChangeListener listener){
      _mgr.removePropertyChangeListener(listener);
    }

    public void setContainer(Container container) {
      _mgr.setContainer(container);
    }

    public Container getContainer() {
      return _mgr.getContainer();
    }
  }
}
