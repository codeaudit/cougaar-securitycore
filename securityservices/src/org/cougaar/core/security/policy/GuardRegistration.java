/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */

package org.cougaar.core.security.policy;

import java.util.*;
import org.w3c.dom.Document;
import java.io.*;

// Cougaar core services
import org.cougaar.planning.ldm.policy.*;
import org.cougaar.core.blackboard.*;
import org.cougaar.core.plugin.*;
import org.cougaar.util.*;

// KAoS policy management
import kaos.core.guard.Guard;
import kaos.core.guard.GuardRetriever;
import kaos.core.enforcer.Enforcer;
import kaos.core.policy.PolicyConstants;
import kaos.core.util.*;

// Cougaar security services
import org.cougaar.core.security.util.DOMWriter;
import org.cougaar.core.security.policy.XMLPolicyCreator;
import org.cougaar.core.security.policy.TypedPolicy;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.provider.SecurityServiceProvider;

public abstract class GuardRegistration
  implements Enforcer
{
  public final String XML_KEY = "XMLContent";
  private SecurityPropertiesService secprop = null;

  /**
   * toggles debugging messages for a vebose mode
   */
  protected boolean debug = true;

  /** The KAoS guard **/
  private Guard guard = null;

  /** The policy type to which we are subscribing
      This is the fully-qualified class name of the policy **/
  private String policyType = null;

  /** The name of the enforcer **/
  private String enforcerName = null;

  public GuardRegistration(String aPolicyType, String enforcerName) {
    // TODO. Modify following line to use service broker instead
    secprop = SecurityServiceProvider.getSecurityProperties(null);

    // Setup whether we're in debug mode or not
    debug = (Boolean.valueOf(secprop.getProperty(secprop.POLICY_DEBUG,
						"false"))).booleanValue();
    setPolicyType(aPolicyType);
    setName(enforcerName);	// Setup the enforcer's name (agent or node)
  }

  /** Set the policy type to which this policy enforcer is subscribing **/
  public void setPolicyType(String aPolicyType) {
    policyType = aPolicyType;
  }

  /** Get the policy type to which this policy enforcer is subscribing **/
  public String getPolicyType() {
    return policyType;
  }

  /** Get the name of this policy enforcer (AgentEnforcer interface)
      Useful for agent enforcer only **/
  public String getName() {
    return enforcerName;
  }

  /** Set the name of this agent-level policy enforcer
      Useful for agent enforcer only **/
  public void setName(String aName) {
    enforcerName = aName;
  }

  /** Obtain a reference to the KAoS guard and register the policy enforcer **/
  public void registerEnforcer()
    throws EnforcerRegistrationException {
    GuardRetriever guardRetriever;

    if (debug == true) {
      // Register the policy enforcer with the guard.
      System.out.println("Registering PolicyEnforcer " +
			 getName() + " to KAoS guard for " + getPolicyType());
    }

    guardRetriever = new GuardRetriever();

    guard = guardRetriever.getGuard();
    if (guard == null) {
      System.err.println("FATAL ERROR: Cannot continue without guard");
      try {
	throw new RuntimeException("ERROR");
      }
      catch (RuntimeException e) {
	e.printStackTrace();
      }
      System.exit(-1);
    }
    // Make sure policy type has been set
    if (getPolicyType() == null) {
      throw new EnforcerRegistrationException("Policy type not specified!");
    }
    guard.registerEnforcer(this, getPolicyType());
    if (debug) {
      System.out.println("Registered for " + getPolicyType());
    }
  }

  /** Receive a policy change from the guard.
   *	Enforcer implementation.
   *    (Enforcer is the interface exposed by enforcers to the guard).
   * @param updateType can be one of SET_POLICIES, ADD_POLICIES,
   *                   CHANGE_POLICIES or REMOVE_POLICIES
   @ @param policies a list of kaos.core.util.PolicyMsg objects
  **/

  public void receivePolicyUpdate(String updateType,
				  List policies)
  //throws PolicyMessageException
  {
    if (debug == true) {
      System.out.println("GuardRegistration. Received " +
			 policies.size() + " policy messages. Type="
			 + updateType);
    }

    Iterator it = policies.iterator();
    while (it.hasNext()) {
      kaos.core.util.PolicyMsg aMsg = (kaos.core.util.PolicyMsg) it.next();
      processPolicyMessage(aMsg);
    }
  }

  private void processPolicyMessage(kaos.core.util.PolicyMsg aMsg)
  {
    Vector attributes = null;

    String policyID = null;
    String policyName = null;
    String policyDescription = null;
    String policyScope = null;
    String policySubjectID = null;
    String policySubjectName =null;
    String policyTargetID = null;
    String policyTargetName = null;
    String policyType = null;

    // Bootstrap policies may not have any of these fields set
    attributes = aMsg.getAttributes();
    policyID =          (String) aMsg.getId();
    policyName =        (String) aMsg.getName();
    policyDescription = (String) aMsg.getDescription();
    policyScope =       (String) aMsg.getScope();
    policySubjectID =   (String) aMsg.getSubjectId();
    policySubjectName = (String) aMsg.getSubjectName();
    policyTargetID =    (String) aMsg.getTargetId();
    policyTargetName =  (String) aMsg.getTargetName();
    policyType =        (String) aMsg.getPolicyType();

    if (debug) {
      System.out.println("Policy Message: " + aMsg.toString());
      System.out.println("policyID:" + policyID);
      System.out.println("policyName:" + policyName);
      System.out.println("policyDescription:" + policyDescription);
      System.out.println("policyScope:" + policyScope);
      System.out.println("policySubjectID:" + policySubjectID);
      System.out.println("policySubjectName:" + policySubjectName);
      System.out.println("policyTargetID:" + policyTargetID);
      System.out.println("policyTargetName:" + policyTargetName);
      System.out.println("policyType:" + policyType);
    }

    if (attributes == null) {
      if (debug == true) {
        System.out.println("GuardEnforcer. Empty policy vector");
      }
      return;
    }

    // Check each message attribute to see if it contains
    // an xml policy document.
    for (int i=0; i<attributes.size(); i++) {
      AttributeMsg attrMsg = (AttributeMsg) attributes.elementAt(i);
      boolean isPolicyProcessed = false;
      String attrName = attrMsg.getName();
      Object attrValue = attrMsg.getValue();

      if (debug) {
	System.out.println("Attr: " + attrName + " - Attr class:"
			   + attrValue.getClass().getName());
      }

      if (attrName.equals("POLICY_OBJECT")) {
	// attrValue should be a Policy object
	if (attrValue instanceof Policy) {
	  processTypedPolicy((Policy)attrValue,
			     policyID, policyName, policyDescription,
			     policyScope,
			     policySubjectID, policySubjectName,
			     policyTargetID, policyTargetName,
			     policyType);
	  isPolicyProcessed = true;
	}
	else {
	  if (debug) {
	    System.out.println("ERROR: unknown policy type");
	  }
	}
      }
      else if (attrName.equals("XMLContent")) {
	// XML policy messages
	processXmlPolicy(attrValue,
			 policyID, policyName, policyDescription,
			 policyScope,
			 policySubjectID, policySubjectName,
			 policyTargetID, policyTargetName,
			 policyType);
	isPolicyProcessed = true;
      }

      if (isPolicyProcessed == false) {
	if (debug) {
	  System.out.println("ERROR: No recognized policy");
	}
      }
    }
  }

  private void processTypedPolicy(Object attribute,
				  String policyID,
				  String policyName,
				  String policyDescription,
				  String policyScope,
				  String policySubjectID,
				  String policySubjectName,
				  String policyTargetID,
				  String policyTargetName,
				  String policyType)
  {
    if (attribute instanceof TypedPolicy) {
      TypedPolicy policy = (TypedPolicy) attribute;
      String policyTypeInMessage = policy.getType();
      if (debug) {
	System.out.println("policyTypeInMessage:" + policyTypeInMessage);
      }
      if (policyType != null && !policyType.equals("")
	  && !policyType.equals(policyTypeInMessage)) {
	// Inconsistency in policy type
	if (debug == true) {
	  System.out.println("GuardRegistration. ERROR. Inconsistent policy types");
	}
	return;
      }
      receivePolicyMessage(policy,
			   policyID, policyName, policyDescription,
			   policyScope,
			   policySubjectID, policySubjectName,
			   policyTargetID, policyTargetName,
			   policyTypeInMessage);
    }
    else {
      // This is not a recognized policy message
      if (debug == true) {
	System.out.println("GuardRegistration. ERROR. Unknown attribute:"
			   + attribute.getClass().getName());
      }
    }
  }

  private void processXmlPolicy(Object attribute,
				String policyID,
				String policyName,
				String policyDescription,
				String policyScope,
				String policySubjectID,
				String policySubjectName,
				String policyTargetID,
				String policyTargetName,
				String policyType)
  {
    if (attribute instanceof Document) {
      Document doc = (Document) attribute;
      //reconstruct the policy from xml doc
      XMLPolicyCreator xpc = new XMLPolicyCreator(doc, "NodeGuard");
      Policy[] p = xpc.getPoliciesByType(policyType);
      if (debug) {
	System.out.println("PolicyCreator.getPoliciesByType returned "
			   + p.length
			   + " policy objects");
      }
      for(int j=0; j<p.length; j++) {
	if (debug) {
	  System.out.println("Calling receivePolicyMessage for "
			     + p[j]
			     + " - Guard type:" + getClass().toString());
	}
	receivePolicyMessage(p[j],
			     policyID, policyName, policyDescription,
			     policyScope,
			     policySubjectID, policySubjectName,
			     policyTargetID, policyTargetName,
			     policyType);
      }
    }
  }

  /**
   * Receive a policy object sent by the Guard.
   * An enforcer registers to its guard with a given policy type. Additionally,
   * agent-level enforcers must implement a getName() method, which must return
   * the name of the agent.
   * The guard sends policies to the enforcer with the type that was provided
   * during the registration.
   * E.g. org.cougaar.core.security.policy.AccessControlPolicy
   * or org.cougaar.core.security.policy.CryptoPolicy
   *
   * Node-level and agent-level enforcers should not register with the same
   * type. Otherwise, the agent enforcer will receive its policy, and the
   * node enforcer will also receive the agent-level policies.
   *
   * A node enforcer may receive policies for both node-level and agent-level
   * policies. In this case, the node enforcer is responsible for the
   * enforcement of agent-level policies. Therefore, there should not also
   * be agent-level enforcers.
   *
   * When a policy is received, the scope can either be domain, node or agent.
   * If the scope is "agent", then the targetID contains the name the agent
   * to which this policy should apply to. If the scope is "node", the
   * targetID will be blank.
   *
   * This class should be defined in the derived class.
   *
   * @param policy             Policy to be enforced by the enforcer.
   * @param policyID           An ID automatically assigned by the domain manager.
   * @param policyName         A user-readable name of the policy.
   * @param policyDecription   A description of the policy.
   * @param policyScope        Either "domain", "node", "agent".
   * @param policySubjectID    The identifier of either a domain, a node or a subject.
   * @param policySubjectName  A user-readable name of the subject.
   * @param policyTargetID     The identifier of the target.
   * @param policyTargetName   A user-readable name of the target.
   * @param policyType         The type of the policy
   */

  public abstract void receivePolicyMessage(Policy policy,
				   String policyID,
				   String policyName,
				   String policyDescription,
				   String policyScope,
				   String policySubjectID,
				   String policySubjectName,
				   String policyTargetID,
				   String policyTargetName,
				   String policyType);
}


