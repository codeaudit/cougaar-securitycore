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

package org.cougaar.core.security.policy.enforcers;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.enforcers.util.AuthSuite;
import org.cougaar.core.security.policy.enforcers.util.DAMLServletMapping;
import org.cougaar.core.security.policy.enforcers.util.HardWired;
import org.cougaar.core.security.policy.enforcers.util.StringPairMapping;
import org.cougaar.core.security.policy.enforcers.util.UserDatabase;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import kaos.ontology.management.UnknownConceptException;
import kaos.ontology.repository.ActionInstanceDescription;
import kaos.ontology.repository.TargetInstanceDescription;
import kaos.policy.information.KAoSProperty;
import safe.enforcer.NodeEnforcer;
import safe.guard.EnforcerManagerService;
import safe.guard.NodeGuard;

/**
 * This class is an Enforcer that intercepts human attempts to access 
 * a servlet.
 */
public class ServletNodeEnforcer
    implements NodeEnforcer
{
  private ServiceBroker _sb;
  protected LoggingService _log;
  private final String _enforcedActionType =
    kaos.ontology.jena.ActionConcepts.actionDamlURL + "AccessAction";
  private final String _authWeak = 
    org.cougaar.core.security.policy.enforcers.ontology.jena.
    EntityInstancesConcepts.EntityInstancesDamlURL + "Weak";
  private final String _authStrong = 
    org.cougaar.core.security.policy.enforcers.ontology.jena.
    EntityInstancesConcepts.EntityInstancesDamlURL + "NSAApprovedProtection";
  private List _people;
  private NodeGuard _guard;
  private DAMLServletMapping _uriMap;
  private Map _userRoleMap;

  /**
   * Returns a list of the classes controlled by this enforcer - currently 
   * CommunicationActions
   */
  public Vector getControlledActionClasses()
  {
    Vector result = new Vector();
    result.add(_enforcedActionType);
    return result;
  }

  /**
   * Name the Enforcer.
   */
  public String getName() { return "Node Enforcer for Servlets"; }


  /**
   * Constructor for this Enforcer - needs a service broker.
   *
   * This function initializes the ServletNodeEnforcer by providing it
   * with a service broker and the names of some people that it is 
   * supposed to manage.  The introduction of the set of people is a
   * temporary hack involving the problem of how policies should be
   * distributed.  Ultimately we will use a different distribution
   * scheme and we will use a SemanticMatcher to test whether a
   * given user is in a given role.
   *
   */
  public ServletNodeEnforcer(ServiceBroker sb) {
    // FIXME!!
    HardWired.setServiceBroker(sb);

    _uriMap = new DAMLServletMapping(sb);
    _uriMap.initializeUri();
    StringPairMapping userRoleStringPairs = new StringPairMapping(sb);
    try {
      _userRoleMap = userRoleStringPairs.loadFunctionalMap("DamlUserRoleMap");
    } catch (IOException e) {
      _log.fatal("Could not initialize role mapping, servlet enforcement " +
                 "enforcer may deny valid access");
    }
    _sb = sb;
    _log = (LoggingService) 
      _sb.getService(this, LoggingService.class, null);
    _people = new Vector();
    for(int i = 0; i < HardWired.users.length; i++) {
      _people.add(HardWired.users[i]);
    }
  }

  /**
   * This method registers the enforcer to the guard and sets up
   * needed variables (such as the service broker and the logging
   * service). 
   *
   * This code used to be in the class 
   *   org.cougaar.core.security.policy.GuardRegistration
   * from securityservices.  I have modified the registerEnforcer
   * call a little - I need to check but I don't think that the
   * previous version works (compiles?) any longer?
   */
  public void registerEnforcer()
  {
    if (!_sb.hasService(EnforcerManagerService.class)) {
      _log.fatal("Guard service is not registered");
      throw new RuntimeException("Guard service is not registered");
    }

    EnforcerManagerService _enfMgr = 
      (EnforcerManagerService)
      _sb.getService(this, EnforcerManagerService.class, null);
    if (_enfMgr == null) {
      _sb.releaseService(this, EnforcerManagerService.class, _enfMgr);
      _log.fatal("Cannot continue without guard", new Throwable());
      throw new RuntimeException("Cannot continue without guard");
    }
    if (!_enfMgr.registerEnforcer(this, _enforcedActionType, _people)) {
      _sb.releaseService(this, EnforcerManagerService.class, _enfMgr);
      _log.fatal("Could not register with the Enforcer Manager Service");
      throw new SecurityException(
                   "Cannot register with Enforcer Manager Service");
    }
    if (_enfMgr instanceof NodeGuard) {
      _guard = (NodeGuard) _enfMgr;
    } else { 
      _sb.releaseService(this, EnforcerManagerService.class, _enfMgr);
      throw new RuntimeException("Cannot get guard");
    }
  }


  /**
   ************************************************************************
   *  Test Code
   */


  private static int minAuth(int auth) {
    int authLevel = AuthSuite.authInvalid;
    if ((auth & AuthSuite.authNoAuth) != 0) {
      authLevel = AuthSuite.authNoAuth;
    } else if ((auth & AuthSuite.authPassword) != 0) {
      authLevel = AuthSuite.authPassword;
    } else if ((auth & AuthSuite.authCertificate) != 0) {
      authLevel = AuthSuite.authCertificate;
    }
    return authLevel;
  }

  /**
   * This is a test that is intended to be run from a servlet.  Its
   * single argument is an output stream on which html will be written.
   *
   * I broke this today - come back to it later...
   */
  public void testEnforcer(PrintWriter out, List uris, List roles) 
    throws IOException, UnknownConceptException
  {
    out.print("<p><b>Servlet Test</b></p>");
    for (Iterator uriIt = uris.iterator();
         uriIt.hasNext();) {
      String uri = (String) uriIt.next();
      out.print("<p><b>--------------------------------------</b></p>");
      out.print("<p>Unknown user is attempting access to " + uri);
      AuthSuite cipherSuites = whichAuthSuite(uri);
      if (cipherSuites == null || cipherSuites.getSSL().size() == 0 ||
          cipherSuites.getAuth() == cipherSuites.authInvalid) {
        out.print("<p>Permission denied " + 
                  "without even determining the user</p>");
      } else {
        AuthSuite suite = cipherSuites;
          out.print("<p>Mediation says enforcer can use:</p><ul>");
          out.print("<li>Ciphers = " + suite.getSSL());
          if ((suite.getAuth() & AuthSuite.authCertificate) != 0) {
            out.print("<li>Certificate");
          } 
          if ((suite.getAuth() & AuthSuite.authPassword) != 0){
            out.print("<li>Password");
          }
          if ((suite.getAuth() & AuthSuite.authNoAuth) != 0) {
            out.print("<li>No Authentication Required");
          }
          out.print("</ul>");
          out.print("<p>Now we find out who the user is.</p>");

          String sslCipher = (String) suite.getSSL().iterator().next();
          int authLevel = minAuth(suite.getAuth());
          for (Iterator rolesIt = roles.iterator();
               rolesIt.hasNext();) {
            String role1 = (String) rolesIt.next();
            HashSet roleSet = new HashSet();
            roleSet.add(role1);

            _log.debug("..servlet...testEnforcer: <p>A user in role " + role1 + " is ");
            if (isActionAuthorized(roleSet, uri, sslCipher, authLevel)) {
              out.print("<p><font color=green>" + 
                        "A user in role " + role1 + " is allowed</font></p>");
              _log.debug("..servlet...testEnforcer: allowed.</p>");
            } else {
              out.print("<p><font color=red>" + 
                        "A user in role " + role1 + " is disallowed</font></p>");
              _log.debug("..servlet...testEnforcer: disallowed.</p>");
            }
            if (false) {
              for (Iterator rolesIt2 = roles.iterator();
                   rolesIt2.hasNext();) {
                String role2 = (String) rolesIt2.next();
                roleSet = new HashSet();
                roleSet.add(role1);
                roleSet.add(role2);
                out.print("<p>A user in role " + role1 + " and "
                          + role2 + " is ");
                if (isActionAuthorized(roleSet, uri, sslCipher, authLevel)) {
                  out.print("allowed.</p>");
                  _log.debug("..servlet...testEnforcer: allowed.</p>");
                } else {
                  out.print("disallowed.</p>");
                  _log.debug("..servlet...testEnforcer: disallowed.</p>");
                }
              }
            }
          }
        out.print("<p><b>--------------------------------------</b></p>");
      }
    }
  }

  // George's Interfaces...

  /**
   * This method checks the policy and recommends an
   * authentication method for a user attempting to use a servlet -
   * given by the uri - using a particular cipher suite.
   * 
   * This method will return an authentication method that will work
   * for some user in some role.  Since the user is not known at
   * this time, the method cannot guarantee that the authentication
   * method will work for all users.  The method will return one of
   * the values
   * <ul>
   *     <li> CipherSuiteWithAuth.authCertificate
   *     <li> CipherSuiteWithAuth.authPassword
   *     <li> CipherSuiteWithAuth.authNoAuth
   *     <li> CipherSuiteWithAuth.authInvalid     (when no authentication method
   *                                       will make the call valid)
   * </ul>
   *
   * This method has incomplete information, so it is possible that
   * it will return an answer that won't work for all users.  Thus
   * for example, a policy might state that users in some roles
   * will be able to access the servlet with a password in the
   * clear.  This function is specified to return an answer that
   * will work for some user in some role.  When the user logs in,
   * the enforcement engine might discover that the user is in a
   * role that should not be able to login with a clear text
   * password.
   *
   * This is a non-optimal situation that highlights the issues
   * involved in writing templates.  A better written template
   * scheme would not be able to express policies that correlate
   * cipher suites with users.
   */
  public AuthSuite whichAuthSuite(String uri) 
  {
    _log.debug("Entering whichAuthSuite");
    
    String kaosuri = (String) _uriMap.ulUriToKAoSUri(uri);
    if (kaosuri == null) {
      _log.warn("Given UL uri mapped to the empty kaos uri");
      return null;
    }

    Set targets = new HashSet();
    if (!targets.add(
                     new TargetInstanceDescription
                     (org.cougaar.core.security.policy.enforcers.ontology.jena.
                      UltralogActionConcepts._accessedServlet_, 
                      kaosuri))) {
      _log.debug("Could not make list of targets - " +
                 "exiting with failure...");
      return null;
    }
    ActionInstanceDescription action = 
      new ActionInstanceDescription(_enforcedActionType,
                                    UserDatabase.anybody(),  
                                    targets);
    action.removeProperty(kaos.ontology.jena.ActionConcepts._performedBy_);
    action.removeAllActorInstances();
    Set cipherSuites = 
      _guard.getAllowableValuesForActionProperty(
                  org.cougaar.core.security.policy.enforcers.ontology.jena.
                  UltralogActionConcepts._usedAuthenticationLevel_,
                  action,
                  HardWired.usedAuthenticationLevelValues,
                  false);
    return HardWired.ulAuthSuiteFromKAoSAuthLevel(cipherSuites);
  }

  /**
   * This function determines whether an attempt of a user to access
   * a servlet is authorized.
   *
   * @param roles - a set of Strings representing roles to which the
   *      user belongs 
   * @param uri - the uri that the user is trying to access
   * @param c - the ciphersuite and authentication mode that the
   *      communication engine is 
   *      using.  
   * 
   * This function is pessimistic in that it will return false on
   * any error.
   */
  public boolean isActionAuthorized(Set roles, 
                                    String uri, 
                                    String sslCipher,
                                    int authLevel) 
  {
    if (_log.isDebugEnabled()) {
      _log.debug("Entering isActionAuthorized with roles = " + roles + 
                 " uri = " + uri + " sslCiphter = " + sslCipher + 
                 " authLevel = " + authLevel);
    }
    String kaosuri = (String) _uriMap.ulUriToKAoSUri(uri);
    if (kaosuri == null) {
      return false;
    }

    Set policyRoles = new HashSet();
    for (Iterator rolesIt = roles.iterator(); rolesIt.hasNext(); ) {
      String role = (String) rolesIt.next();
      String policyRole = (String) _userRoleMap.get(role);
      if (policyRole == null && _log.isWarnEnabled()) {
        _log.warn("No policyrole for the Ultralog role :" + role);
      } else {
        policyRoles.add(policyRole);
      }
    }

    String user = UserDatabase.login(policyRoles);
    if (_log.isDebugEnabled()) {
      _log.debug("Obtained user = " + user);
    }
        
    Set targets = new HashSet();
    if (!targets.add(new TargetInstanceDescription
                     (org.cougaar.core.security.policy.enforcers.ontology.jena.
                      UltralogActionConcepts._accessedServlet_, 
                      kaosuri)) ) {
      _log.debug("Could not make list of targets - " +
                 "exiting with failure...");
      return false;
    }
    if (!HardWired.addAuthSuiteTarget(targets, sslCipher, authLevel)) {
      return false;
    }
    ActionInstanceDescription action = 
      new ActionInstanceDescription(_enforcedActionType,
                                    user,  
                                    targets);
    KAoSProperty userProp = action.getProperty(kaos.ontology.jena.
                                               ActionConcepts._performedBy_);
    try {
      boolean result = _guard.isActionAuthorized(action);
      UserDatabase.logout(user);
      return result;
    } catch (Throwable th) {
      _log.error("Error testing if action is authorized", th);
      return false;
    }
  }
}
