package org.cougaar.core.security.policy.enforcers;

import org.cougaar.core.security.policy.enforcers.ontology.*;
import org.cougaar.core.security.policy.enforcers.util.CypherSuite;
import org.cougaar.core.security.policy.enforcers.util.CypherSuiteWithAuth;
import org.cougaar.core.security.policy.enforcers.util.DAMLMapping;
import org.cougaar.core.security.policy.enforcers.util.HardWired;
import org.cougaar.core.security.policy.enforcers.util.UserDatabase;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;

import kaos.core.util.AttributeMsg;
import kaos.core.util.SubjectListedPolicyMsg;
import kaos.ontology.jena.ActionConcepts;
import kaos.ontology.matching.*;
import kaos.policy.information.KAoSProperty;
import kaos.policy.information.PolicyInformation;

import safe.ontology.jena.UltralogActionConcepts;

// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.planning.ldm.policy.RuleParameter;

// KAoS policy management
import kaos.ontology.management.UnknownConceptException;
import kaos.ontology.repository.ActionInstanceDescription;
import kaos.ontology.repository.TargetInstanceDescription;
import kaos.policy.guard.PolicyDistributor;

import safe.enforcer.AgentEnforcer;
import safe.enforcer.NodeEnforcer;
import safe.guard.EnforcerManagerService;
import safe.guard.NodeGuard;

/**
 * This class is an Enforcer that intercepts human attempts to access 
 * a servlet.
 */
public class ServletNodeEnforcer
    implements NodeEnforcer, PolicyDistributor
{
  private ServiceBroker _sb;
  protected LoggingService _log;
  private final String _enforcedActionType = ActionConcepts.actionDamlURL 
    + "AccessAction";
  private final String _authWeak = 
    EntityInstancesConcepts.EntityInstancesDamlURL + "Weak";
  private final String _authStrong = 
    EntityInstancesConcepts.EntityInstancesDamlURL + "NSAApprovedProtection";
  private List _people;
  private NodeGuard _guard;
  private DAMLMapping _uriMap;

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

    _uriMap = new DAMLMapping(sb);
    _uriMap.initializeUri();

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
   * This method receives policy updates from the guard.
   *
   * This method is responsible for collecting the set of currently
   * active policies together into a sorted set (sorted by
   * priority).  It then uses that sorted list to answer questions
   * about the policy.
   */
  public void receivePolicyUpdate(String updateType, List policies)
  {
    _log.info("ServletNodeEnforcer:This dummy got the message (err... policy)");
    Iterator policyIterator = policies.iterator();
    while (policyIterator.hasNext()) {
      Object policyObject = policyIterator.next();
      _log.info("ServletNodeEnforcer:---------A Policy--------------");
      _log.info("ServletNodeEnforcer:Update type = " + updateType);
      if (!(policyObject instanceof SubjectListedPolicyMsg)) {
        _log.debug(".ServletNodeEnforcer:Don't handle this type of message");
        return;
      }
      SubjectListedPolicyMsg policy = (SubjectListedPolicyMsg) policyObject;
      Iterator subjectIterator 
        = policy.getApplicableSubjectIDs().iterator();
      while (subjectIterator.hasNext()) {
        _log.info("ServletNodeEnforcer:Subject = " + subjectIterator.next());
      }
      Iterator attributeIterator
        = policy.getAttributes().iterator();
      while (attributeIterator.hasNext()) {
        AttributeMsg attribute
          = (AttributeMsg) attributeIterator.next();
        if (attribute.getName()
            .equals(AttributeMsg.POLICY_INFORMATION)) {
          PolicyInformation policyInfo
            = (PolicyInformation) attribute.getValue();
          _log.info("ServletNodeEnforcer:Modality = " + 
                    policyInfo.getModality());
          _log.info("ServletNodeEnforcer:Priority = " +
                    policyInfo.getPriority());
          for (Enumeration properties 
                 = policyInfo.getAllProperties();
               properties.hasMoreElements();) {
            KAoSProperty property = 
              (KAoSProperty) properties.nextElement();
            _log.info("ServletNodeEnforcer:KAoS property name = "
                      + property.getPropertyName());
            _log.info("ServletNodeEnforcer:KAoS class name = " 
                      + property.getClassName());
            Iterator instanceIt 
              = property.getAllInstances().iterator();
            while (instanceIt.hasNext()) {
              _log.info("ServletNodeEnforcer:Instance = "
                        + instanceIt.next());
            }
            _log.info("ServletNodeEnforcer:Complement? " + 
                      property.isComplement());
          }
        } else {
          _log.info("ServletNodeEnforcer:--------------Name/Value----------");
          _log.info("ServletNodeEnforcer:Name = " +  attribute.getName()
                    + " with type " + 
                    attribute.getName()
                    .getClass().toString());
          _log.info("ServletNodeEnforcer:Value = " + attribute.getValue()
                    + " with type "
                    + attribute.getValue()
                    .getClass().toString());
          _log.info("ServletNodeEnforcer:Selected = " 
                    + attribute.isSelected());
        }
      }
    }
  }

  /**
   ************************************************************************
   *  Test Code
   */


  /** 
   * Broken for now...
   */
  public void testTiming(PrintWriter out)
  {
    out.print("<p><b>Mildly Broken for now! Fix me...</b></p>");
    String role1 = HardWired.ulRoles[0];
    String role2 = HardWired.ulRoles[1];
    Set roles = new HashSet();
    roles.add(role1);
    roles.add(role2);
    out.print("<p><b>Timing Check</b></p>");

    String uri = null;
    for (Iterator uriIt = HardWired.uriMap.keySet().iterator();
         uriIt.hasNext();) {
      uri = (String) uriIt.next();
      break;
    }

    boolean firstStepOnly = false;
    CypherSuiteWithAuth cypher = null;
    Set cyphers = whichCypherSuiteWithAuth(uri);
    if (cyphers == null || cyphers.size() == 0) {
      firstStepOnly = true;
      out.print("<p>No cyphers found: only doing the first step</p>");
    } else {
      for (Iterator cyphersIt = cyphers.iterator();
           cyphersIt.hasNext();) {
        cypher = (CypherSuiteWithAuth) cyphersIt.next();
        break;
      }
    }

    boolean allowed = false;
    int     count   = 2000;
    long start = System.currentTimeMillis();
    for (int i = 0; i < count; i++) {
      cyphers = whichCypherSuiteWithAuth(uri);
      if (!firstStepOnly) {
        allowed=isActionAuthorized(roles, uri, cypher);
      }
    }
    long duration = System.currentTimeMillis() - start;
    out.print("<p>" + count + " calls mediated in " 
              + duration + " milliseconds.</p>");
    out.print("<p>Last call returned the following results: </p>");
    if (cyphers == null || cyphers.size() == 0) {
      out.print("<p>No user is allowed access</p>");
    } else {
      out.print("<p>Is user in roles " + role1 + " and " + role2 +
                " using cipher suite <ul>");
      out.print("<li>Symmetric = " + cypher.getSymmetric());
      out.print("<li>Asymmetric = " + cypher.getAsymmetric());
      out.print("<li>Checksum = " + cypher.getChecksum());
      out.print("<li>");
      if (cypher.getAuth() == CypherSuiteWithAuth.authCertificate) {
        out.print("Certificate");
      } else if (cypher.getAuth() 
                 == CypherSuiteWithAuth.authPassword){
        out.print("Password");
      } else if (cypher.getAuth() == CypherSuiteWithAuth.authNoAuth) {
        out.print("No Authentication Required");
      }
      out.print("</ul>");
      out.print("allowed access?</p>");
      out.print("" + allowed);
    }
  }

  /**
   * This is a test that is intended to be run from a servlet.  Its
   * single argument is an output stream on which html will be written.
   *
   * I broke this today - come back to it later...
   */
  public void testEnforcer(PrintWriter out) 
    throws IOException, UnknownConceptException
  {
    out.print("<p><b>Mildly Broken for now! Fix me...</b></p>");
    out.print("<p><b>Servlet Test</b></p>");
    Set uris = HardWired.uriMap.keySet();
    for (Iterator uriIt = uris.iterator();
         uriIt.hasNext();) {
      String uri = (String) uriIt.next();
      out.print("<p><b>--------------------------------------</b></p>");
      out.print("<p>Unknown user is attempting access to " + uri);
      Set cypherSuites = whichCypherSuiteWithAuth(uri);
      if (cypherSuites == null || cypherSuites.size() == 0) {
        out.print("<p>Permission denied " + 
                  "without even determining the user</p>");
      } else {
        for (Iterator cypherIt = cypherSuites.iterator();
             cypherIt.hasNext();) {
          CypherSuiteWithAuth suite
            = (CypherSuiteWithAuth) cypherIt.next();
          out.print("<p>Mediation says enforcer can use:</p><ul>");
          out.print("<li>Symmetric = " + suite.getSymmetric());
          out.print("<li>Asymmetric = " + suite.getAsymmetric());
          out.print("<li>Checksum = " + suite.getChecksum());
          out.print("<li>");
          if (suite.getAuth() == CypherSuiteWithAuth.authCertificate) {
            out.print("Certificate");
          } else if (suite.getAuth() 
                     == CypherSuiteWithAuth.authPassword){
            out.print("Password");
          } else if (suite.getAuth() == CypherSuiteWithAuth.authNoAuth) {
            out.print("No Authentication Required");
          }
          out.print("</ul>");
          out.print("<p>Now we find out who the user is.</p>");

          int roleCount = HardWired.ulRoles.length;
          for (int i = 0; i < roleCount; i++) {
            String role1 = HardWired.ulRoles[i];
            HashSet roleSet = new HashSet();
            roleSet.add(role1);
            out.print("<p>A user in role " + role1 + " is ");
            _log.debug("..servlet...testEnforcer: <p>A user in role " + role1 + " is ");
            if (isActionAuthorized(roleSet, uri, suite)) {
              out.print("allowed.</p>");
              _log.debug("..servlet...testEnforcer: allowed.</p>");
            } else {
              out.print("disallowed.</p>");
              _log.debug("..servlet...testEnforcer: disallowed.</p>");
            }
            for (int j = i+1; j < roleCount; j++) {
              String role2 = HardWired.ulRoles[j];
              roleSet = new HashSet();
              roleSet.add(role1);
              roleSet.add(role2);
              out.print("<p>A user in role " + role1 + " and "
                        + role2 + " is ");
              if (isActionAuthorized(roleSet, uri, suite)) {
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
   * given by the uri - using a particular cypher suite.
   * 
   * This method will return an authentication method that will work
   * for some user in some role.  Since the user is not known at
   * this time, the method cannot guarantee that the authentication
   * method will work for all users.  The method will return one of
   * the values
   * <ul>
   *     <li> CypherSuiteWithAuth.authCertificate
   *     <li> CypherSuiteWithAuth.authPassword
   *     <li> CypherSuiteWithAuth.authNoAuth
   *     <li> CypherSuiteWithAuth.authInvalid     (when no authentication method
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
   * cypher suites with users.
   */
  public Set whichCypherSuiteWithAuth(String uri) 
  {
    _log.debug("Entering whichCypherSuiteWithAuth");
    
    String kaosuri = (String) _uriMap.ulUriToKAoSUri(uri);
    if (kaosuri == null) {
      _log.warn("Given UL uri mapped to the empty kaos uri");
      return null;
    }

    Set targets = new HashSet();
    if (!targets.add(
                     new TargetInstanceDescription
                     (UltralogActionConcepts._accessedServlet_, 
                      kaosuri))) {
      _log.debug("Could not make list of targets - " +
                 "exiting with failure...");
      return null;
    }
    ActionInstanceDescription action = 
      new ActionInstanceDescription(_enforcedActionType,
                                    UserDatabase.anybody(),  
                                    targets);
    action.removeProperty(ActionConcepts._performedBy_);
    action.removeAllActorInstances();
    Set cypherSuites = 
      _guard.getAllowableValuesForActionSingleTim(
                  UltralogActionConcepts._usedAuthenticationLevel_,
                  action,
                  HardWired.usedAuthenticationLevelValues);
    return HardWired.ulCiphersWithAuthFromKAoSAuthLevel(cypherSuites);
  }

  /**
   * This function determines whether an attempt of a user to access
   * a servlet is authorized.
   *
   * @param roles - a set of Strings representing roles to which the
   *      user belongs 
   * @param uri - the uri that the user is trying to access
   * @param c - the cyphersuite and authentication mode that the
   *      communication engine is 
   *      using.  
   * 
   * This function is pessimistic in that it will return false on
   * any error.
   */
  public boolean isActionAuthorized(Set roles, 
                                    String uri, 
                                    CypherSuiteWithAuth c) 
  {
    String kaosuri = (String) _uriMap.ulUriToKAoSUri(uri);
    if (kaosuri == null) {
      return false;
    }

    String user = UserDatabase.login(roles);
        
    Set targets = new HashSet();
    if ( !targets.add(
                      new TargetInstanceDescription
                      (UltralogActionConcepts._accessedServlet_, 
                       kaosuri)) ) {
      _log.debug("Could not make list of targets - " +
                 "exiting with failure...");
      return false;
    }
    if (!HardWired.addCypherSuiteWithAuthTarget(targets, c)) {
      return false;
    }
    ActionInstanceDescription action = 
      new ActionInstanceDescription(_enforcedActionType,
                                    user,  
                                    targets);
    KAoSProperty userProp = action.getProperty(ActionConcepts._performedBy_);
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
