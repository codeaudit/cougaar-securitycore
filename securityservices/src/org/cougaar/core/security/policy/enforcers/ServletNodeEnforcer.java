package org.cougaar.core.security.policy.enforcers;

import org.cougaar.core.security.policy.enforcers.ontology.*;
import org.cougaar.core.security.policy.enforcers.util.CypherSuite;
import org.cougaar.core.security.policy.enforcers.util.CypherSuiteWithAuth;
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
    public void registerEnforcer() throws RuntimeException
    {
	if (!_sb.hasService(EnforcerManagerService.class)) {
	    _log.fatal("Guard service is not registered");
	    throw new RuntimeException("Guard service is not registered");
	}

	EnforcerManagerService _enfMgr = 
	    (EnforcerManagerService)
	    _sb.getService(this, EnforcerManagerService.class, null);
	if (_enfMgr == null) {
	    _log.fatal("Cannot continue without guard", new Throwable());
	    throw new RuntimeException("Cannot continue without guard");
	}
	if (!_enfMgr.registerEnforcer(this, _enforcedActionType, _people)) {
	    _log.fatal("Could not register with the Enforcer Manager Service");
	    throw new RuntimeException("Cannot register with Enforcer Manager Service");
	}
	if (_enfMgr instanceof NodeGuard) {
	    _guard = (NodeGuard) _enfMgr;
	} else { 
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
	_log.info("This dummy got the message (err... policy)");
	Iterator policyIterator = policies.iterator();
	while (policyIterator.hasNext()) {
	    _log.info("---------A Policy--------------");
	    _log.info("Update type = " + updateType);
	    SubjectListedPolicyMsg policy = 
		(SubjectListedPolicyMsg) policyIterator.next();
	    Iterator subjectIterator 
		= policy.getApplicableSubjectIDs().iterator();
	    while (subjectIterator.hasNext()) {
		_log.info("Subject = " + subjectIterator.next());
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
		    _log.info("Modality = " + 
				       policyInfo.getModality());
		    _log.info("Priority = " +
				       policyInfo.getPriority());
		    for (Enumeration properties 
			     = policyInfo.getAllProperties();
			 properties.hasMoreElements();) {
			KAoSProperty property = 
			    (KAoSProperty) properties.nextElement();
			_log.info("KAoS property name = "
					   + property.getPropertyName());
			_log.info("KAoS class name = " 
					   + property.getClassName());
			Iterator instanceIt 
			    = property.getAllInstances().iterator();
			while (instanceIt.hasNext()) {
			    _log.info("Instance = "
					       + instanceIt.next());
			}
			_log.info("Complement? " + 
					   property.isComplement());
		    }
		} else {
		    _log.info("--------------Name/Value----------");
		    _log.info("Name = " +  attribute.getName()
				       + " with type " + 
				       attribute.getName()
				         .getClass().toString());
		    _log.info("Value = " + attribute.getValue()
				       + " with type "
				       + attribute.getValue()
				           .getClass().toString());
		    _log.info("Selected = " + attribute.isSelected());
		}
	    }
	}
    }

    private void testOld(PrintWriter out)
	throws IOException, UnknownConceptException
    {
	Set targetsWeak = new HashSet();
	String person    = (String) _people.get(0);
	TargetInstanceDescription targetWeak = 
	    new TargetInstanceDescription(UltralogActionConcepts._usedProtectionLevel_, _authWeak);
	if (! targetsWeak.add(targetWeak)) {
	    out.print("<p>Could not make list of targets - exiting...</p>");
	    return;
	}
	ActionInstanceDescription actionWeak = 
	    new ActionInstanceDescription(_enforcedActionType, 
					  person,
					  targetsWeak);
	out.print("<p>Testing isActionAuthorized...</p>");
	out.print("<p>Communications from " + person + " are ");
	if (_guard.isActionAuthorized(actionWeak)) {
	    out.print("Allowed");
	} else {
	    out.print("Disallowed");
	}
	out.print(" if authentication is weak</p>");

	Set targetsStrong = new HashSet();
	TargetInstanceDescription targetStrong = 
	    new TargetInstanceDescription(UltralogActionConcepts._usedProtectionLevel_, _authStrong);
	if (! targetsStrong.add(targetStrong)) {
	    out.print("<p>Could not make list of targets - exiting...</p>");
	    return;
	}
	ActionInstanceDescription actionStrong = 
	    new ActionInstanceDescription(_enforcedActionType, 
					  person,
					  targetsStrong);
	out.print("<p>Testing isActionAuthorized...</p>");
	out.print("<p>Communications from " + person + " are ");
	if (_guard.isActionAuthorized(actionStrong)) {
	    out.print("Allowed");
	} else {
	    out.print("Disallowed");
	}
	out.print(" if authentication is strong</p>");
    }

    /**
     * This is a test that is intended to be run from a servlet.  Its
     * single argument is an output stream on which html will be written.
     */
    public void testEnforcer(PrintWriter out) 
	throws IOException, UnknownConceptException
    {
	testOld(out);
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
    public int whichAuthenticationMethod(String uri, CypherSuite c) 
    {
	String kaosuri = (String) HardWired.uriMap.get(uri);
	if (kaosuri == null) {
	    return CypherSuiteWithAuth.authInvalid;
	}

	Set targets = new HashSet();
	if (!targets.add(
	       new TargetInstanceDescription
		       (UltralogActionConcepts._hasSubject_, 
		        kaosuri))) {
	    _log.debug("Could not make list of targets - " +
		       "exiting with failure...");
	    return CypherSuiteWithAuth.authInvalid;
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
	return CypherSuiteWithAuth.authPassword;
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
				      CypherSuiteWithAuth c) {
	String kaosuri = (String) HardWired.uriMap.get(uri);
	if (kaosuri == null) {
	    return false;
	}

	Set kaosroles = new HashSet();
	for (Iterator roleIt = roles.iterator(); roleIt.hasNext();) {
	    kaosroles.add(HardWired.kaosRoleFromRole((String) roleIt.next()));
	}
	
	Set targets = new HashSet();
	if ( !targets.add(
	        new TargetInstanceDescription
		        (UltralogActionConcepts._hasSubject_, 
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
					  UserDatabase.anybody(),  
					  targets);
	KAoSProperty userProp = action.getProperty(ActionConcepts._performedBy_);
	try {
	    return _guard.isActionAuthorized(action);
	} catch (Throwable th) {
	    th.printStackTrace();
	    return false;
	}
    }

    /**
     * This function is called after a failed access attempt to see if
     * there is a choice of cyphersuite that would have achieved a
     * better result.
     *
     * @param roles - a set of Strings representing the roles the user
     * belongs to
     *
     * @param uri - the uri of the servlet being accessed.
     *
     * @returns a set of CypherSuitesWithAuth (cyphersuites and
     * authentication modes) indicating what
     * would have allowed the login.  A null return indicates failure.
     */
    public Set allowedCypherSuites(Set roles,
				   String uri) 
    {

	String kaosuri = (String) HardWired.uriMap.get(uri);
	if (kaosuri == null) {
	    return null;
	}

	Set kaosroles = new HashSet();
	for (Iterator roleIt = roles.iterator(); roleIt.hasNext();) {
	    kaosroles.add(HardWired.kaosRoleFromRole((String) roleIt.next()));
	}
	String user = UserDatabase.login(kaosroles);

	Set    targets = new HashSet();
	if (!targets.add(
	       new TargetInstanceDescription
		       (UltralogActionConcepts._hasSubject_, 
		        kaosuri))) {
	    _log.debug("Could not make list of targets - " +
		       "exiting with failure...");
	    return null;
	}
	ActionInstanceDescription action = 
	    new ActionInstanceDescription(_enforcedActionType,
					  user,  
					  targets);
	KAoSProperty userProp = action.getProperty(ActionConcepts._performedBy_);
	Set authlevels = 
	    _guard.getAllowableValuesForActionSingleTim(
		  UltralogActionConcepts._usedAuthenticationLevel_,
		  action,
		  HardWired.usedAuthenticationLevelValues);
	Set suites = new HashSet();
	for (Iterator authlevelIt = authlevels.iterator(); 
	     authlevelIt.hasNext();) {
	    suites.addAll((Collection)
			     (HardWired.usedAuthenticationLevelMap
			      .get((String) authlevelIt.next())));
	}
	return suites;
    }

}
