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

package com.nai.security.policy;

import java.util.*;
import org.w3c.dom.Document;
import java.io.*;

import org.cougaar.planning.ldm.policy.*;
import org.cougaar.core.blackboard.*;
import org.cougaar.core.plugin.*;
import org.cougaar.core.security.policy.XMLPolicyCreator;
import org.cougaar.util.*;

import kaos.core.guard.Guard;
import kaos.core.guard.GuardRetriever;
import kaos.core.enforcer.Enforcer;
import kaos.core.policy.PolicyConstants;
import kaos.core.util.*;

import com.nai.security.util.DOMWriter;

public abstract class GuardRegistration
  implements Enforcer
{
  public final String XML_KEY = "XMLContent";

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
      // Setup whether we're in debug mode or not
      debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.policy.debug",
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

    try {
      guardRetriever = new GuardRetriever();
      guard = guardRetriever.getGuard();
      if (guard == null) {
	System.err.println("ERROR: Cannot continue secure execution without guard");
	try {
	  throw new EnforcerRegistrationException("Guard Unavailable");
	}
	catch (EnforcerRegistrationException e) {
	  e.printStackTrace();
	}
	System.exit(-1);
      }
      // Make sure policy type has been set
      if (getPolicyType() == null) {
	throw new EnforcerRegistrationException("Policy type not specified!");
      }
      guard.registerEnforcer(this, getPolicyType());
    } catch (NullPointerException e) {
      throw new EnforcerRegistrationException("Guard Unavailable");
    }
  }

  /** Receive a policy change from the guard.
   *	IEnforcer implementation.
   *    (IEnforcer is the interface exposed by enforcers to the guard).
   * @param updateType can be one of SET_POLICIES, ADD_POLICIES,
   *                   CHANGE_POLICIES or REMOVE_POLICIES
   @ @param policies a list of kaos.core.util.PolicyMsg objects
  **/

  public void receivePolicyUpdate(String updateType,
				  List policies)
  //throws PolicyMessageException
  {
    if (debug == true) {
      System.out.println("GuardEnforcer. Received a list of policy msg. Type="
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
    String policyTypeInMessage = null;

    String policyID = null;
    String policyName = null;
    String policyDescription = null;
    String policyScope = null;
    String policySubjectID = null;
    String policySubjectName =null;
    String policyTargetID = null;
    String policyTargetName = null;
    String policyType = null;

    try {
      attributes = aMsg.getAttributes();
      policyTypeInMessage = (String) aMsg.getSymbol(PolicyConstants.HLP_POLICY_TYPE);
      policyID =          (String) aMsg.getId();
      policyName =        (String) aMsg.getName();
      policyDescription = (String) aMsg.getDescription();
      policyScope =       (String) aMsg.getScope();
      policySubjectID =   (String) aMsg.getSubjectId();
      policySubjectName = (String) aMsg.getSubjectName();
      policyTargetID =    (String) aMsg.getTargetId();
      policyTargetName =  (String) aMsg.getTargetName();
      policyType =        (String) aMsg.getPolicyType();

    } catch (kaos.core.util.SymbolNotFoundException e) {
      if (debug == true) {
	System.out.println("GuardEnforcer. Unknown policy type: " + e);
	e.printStackTrace();
      }
      return;
    }
    if (debug) {
      System.out.println("policyTypeInMessage:" + policyTypeInMessage);
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

    if (policyType.equals(policyTypeInMessage) == false) {
      // Incorrect policy message
      if (debug == true) {
	System.out.println("GuardEnforcer. Inconsistent types in policy message");
      }
      return;
    }

    if (attributes == null) {
      if (debug == true) {
        System.out.println("GuardEnforcer. Empty policy vector");
      }
      return;
    }

    //check each message attribute to see if it contains an xml policy  document
    for (int i=0; i<attributes.size(); i++) {
      Msg attrMsg = (Msg) attributes.elementAt(i);
      if (debug) {
	System.out.println("Policy type: " + policyType);
      }
      Object policy = null;
      try {
	policy = attrMsg.getSymbol("POLICY_OBJECT");
      }
      catch (SymbolNotFoundException e) {
	// This is not an policy message
      }
      if (policy instanceof Policy) {
	receivePolicyMessage((Policy) policy,
			     policyID, policyName, policyDescription,
			     policyScope,
			     policySubjectID, policySubjectName,
			     policyTargetID, policyTargetName,
			     policyType);
      }
      else {
	// This is not a recognized policy message
      }

      // XML policy messages
      try {
	policy = attrMsg.getSymbol("XMLContent");
      }
      catch (SymbolNotFoundException e) {
	// This is not an XMLpolicy message
      }
      if (policy instanceof Document) {
        Document doc = (Document) policy;
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
  }




  /**
   * Receive a policy object sent by the Guard.
   * An enforcer registers to its guard with a given policy type. Additionally,
   * agent-level enforcers must implement a getName() method, which must return
   * the name of the agent.
   * The guard sends policies to the enforcer with the type that was provided
   * during the registration.
   * E.g. com.nai.security.policy.AccessControlPolicy
   * or com.nai.security.policy.CryptoPolicy
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


