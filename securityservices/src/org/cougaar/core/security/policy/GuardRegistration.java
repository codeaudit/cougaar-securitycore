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
import org.apache.xml.serialize.XMLSerializer;
import java.io.*;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.planning.ldm.policy.*;
import org.cougaar.core.blackboard.*;
import org.cougaar.core.plugin.*;
import org.cougaar.util.*;

// KAoS policy management
import kaos.policy.guard.*;
import kaos.policy.enforcement.Enforcer;
import kaos.policy.util.PolicyConstants;
import kaos.core.util.*;

// Cougaar security services
import org.cougaar.core.security.util.DOMWriter;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.provider.SecurityServiceProvider;

public abstract class GuardRegistration
  implements Enforcer
{
  public final String XML_KEY = "XMLContent";
  private SecurityPropertiesService secprop = null;
  private ServiceBroker serviceBroker;
  protected LoggingService log;
  private ConfigParserService cps = null;

  /** The KAoS guard **/
  private EnforcerManager guard = null;

  /** The policy type to which we are subscribing
      This is the fully-qualified class name of the policy **/
  private String policyType = null;

  /** The name of the enforcer **/
  private String enforcerName = null;

  public GuardRegistration(String aPolicyType, String enforcerName,
			   ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class, null);

    cps = (ConfigParserService)
      serviceBroker.getService(this,
			       ConfigParserService.class, null);

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

    if (log.isDebugEnabled() == true) {
      // Register the policy enforcer with the guard.
      log.debug("Registering PolicyEnforcer " +
		getName() + " to KAoS guard for " + getPolicyType());
    }

    guardRetriever = new GuardRetriever();
    guard = guardRetriever.getGuard();
    if (guard == null) {
      log.error("FATAL ERROR: Cannot continue without guard");
      throw new RuntimeException("ERROR: Cannot continue without guard");
    }
    // Make sure policy type has been set
    if (getPolicyType() == null) {
      throw new EnforcerRegistrationException("Policy type not specified!");
    }
    SubjectMsg sm = new SubjectMsg(getName(),getName(),"scope");
    Vector v = new Vector();
    v.add(sm);
    EnforcementCapabilityMsg ecm =
      new EnforcementCapabilityMsg(getPolicyType(),v);
    guard.registerEnforcer(this, ecm);
    if (log.isDebugEnabled()) {
      log.debug("Registered for " + getPolicyType());
    }
  }

  /** Receive a policy change from the guard.
   *	Enforcer implementation.
   *    (Enforcer is the interface exposed by enforcers to the guard).
   * @param updateType can be one of SET_POLICIES, ADD_POLICIES,
   *                   CHANGE_POLICIES or REMOVE_POLICIES
   * @param policies a list of kaos.core.util.PolicyMsg objects
   **/

  public void receivePolicyUpdate(String updateType,
				  List policies)
  //throws PolicyMessageException
  {
    if (log.isDebugEnabled()) {
      log.debug("GuardRegistration. Received " +
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

    if (aMsg == null || aMsg.getAttributes() == null) {
      return;
    }
    // Bootstrap policies may not have any of these fields set
    attributes = aMsg.getAttributes();
    policyID =          (String) aMsg.getId();
    policyName =        (String) aMsg.getName();
    policyDescription = (String) aMsg.getDescription();
    policyType =        (String) aMsg.getType();
 
    if (log.isDebugEnabled()) {
      log.debug("Policy Message: " + aMsg.toString());
      log.debug("policyID:" + policyID);
      log.debug("policyName:" + policyName);
      log.debug("policyDescription:" + policyDescription);
      log.debug("policyScope:" + policyScope);
      log.debug("policySubjectID:" + policySubjectID);
      log.debug("policySubjectName:" + policySubjectName);
      log.debug("policyTargetID:" + policyTargetID);
      log.debug("policyTargetName:" + policyTargetName);
      log.debug("policyType:" + policyType);
    }

    if (attributes == null) {
      if (log.isErrorEnabled()) {
        log.error("GuardEnforcer. Empty policy vector");
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

      if (log.isDebugEnabled()) {
	log.debug("Attr: " + attrName + " - Attr class:"
		  + attrValue.getClass().getName());
      }

      if (attrName.equals("POLICY_OBJECT")) {
	// attrValue should be a Policy object
	if (attrValue instanceof Policy
	    || attrValue instanceof SecurityPolicy) {
	  processTypedPolicy(attrValue,
			     policyID, policyName, policyDescription,
			     policyScope,
			     policySubjectID, policySubjectName,
			     policyTargetID, policyTargetName,
			     policyType);
	  isPolicyProcessed = true;
	}
	else {
	  if (log.isErrorEnabled()) {
	    log.error("Unknown policy type");
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
	if (log.isErrorEnabled()) {
	  log.error("No recognized policy");
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
    if (log.isDebugEnabled()) {
      log.debug("policyTypeInMessage:" + attribute);
    }
    if(attribute instanceof SecurityPolicy) {
      SecurityPolicy policy = (SecurityPolicy) attribute;
      receivePolicyMessage(policy,
			   policyID, policyName, policyDescription,
			   policyScope,
			   policySubjectID, policySubjectName,
			   policyTargetID, policyTargetName,
			   policyType);
    }else if(attribute instanceof Policy) {
      Policy policy = (Policy) attribute;
      receivePolicyMessage(policy,
			   policyID, policyName, policyDescription,
			   policyScope,
			   policySubjectID, policySubjectName,
			   policyTargetID, policyTargetName,
			   policyType);
    }else{
      // This is not a recognized policy message
      if (log.isErrorEnabled()) {
    	log.error("GuardRegistration. ERROR. Unknown attribute:"
		  + attribute.getClass().getName());
      }
      return;
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
    if (!(attribute instanceof Document)) return;
    Document doc = (Document) attribute;
    Class pt = null;
    Object obj = null;
    try{
      pt = Class.forName(policyType); 
      obj = pt.newInstance();
    }catch(Exception e){
      if (log.isErrorEnabled()) 
        log.error("GuardRegistration-processXmlPolicy:received unknown Type:"
		  + policyType);
    }
    
    if(obj instanceof Policy){
      //reconstruct the policy from xml doc
      XMLPolicyCreator xpc = new XMLPolicyCreator(doc, "NodeGuard");
      Policy[] p = xpc.getPoliciesByType(policyType);
      if (log.isDebugEnabled()) {
        log.debug("PolicyCreator.getPoliciesByType returned "
		  + p.length
		  + " policy objects");
      }
      for(int j=0; j<p.length; j++) {
        if (log.isDebugEnabled()) {
        log.debug("Calling receivePolicyMessage for "
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
    }else if(obj instanceof SecurityPolicy){
      //get InputStream back for the parser
      byte[] ba; 
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      try{
        XMLSerializer serializer = new XMLSerializer();
        serializer.setOutputByteStream(out);
        serializer.serialize(doc);
      }catch(Exception e){
      if (log.isErrorEnabled()) 
        log.error("GuardRegistration-processXmlPolicy:failed getting DOM Stream:"
          + e.getMessage());
      }
      ba = out.toByteArray();
      ByteArrayInputStream in = new ByteArrayInputStream(ba);
      cps.parsePolicy(in);
      SecurityPolicy[] p = cps.getSecurityPolicies(pt);
      
      if (log.isDebugEnabled()) {
        log.debug("PolicyCreator.getPoliciesByType returned "
		  + p.length
		  + " policy objects");
      }
      for(int j=0; j<p.length; j++) {
        if (log.isDebugEnabled()) {
        log.debug("Calling receivePolicyMessage for "
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

  public /*abstract*/ void receivePolicyMessage(SecurityPolicy policy,
				   String policyID,
				   String policyName,
				   String policyDescription,
				   String policyScope,
				   String policySubjectID,
				   String policySubjectName,
				   String policyTargetID,
				   String policyTargetName,
				   String policyType){};
}


