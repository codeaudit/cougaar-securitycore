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

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Vector;
import java.util.Iterator;
import java.io.*;

import org.w3c.dom.Document;

// Core Cougaar
import org.cougaar.core.plugin.SimplePlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.planning.ldm.policy.Policy;

// KAoS policy management
import kaos.core.util.Msg;
import kaos.core.policy.PolicyConstants;
import kaos.core.util.Logger;
import kaos.core.util.PolicyMsg;
import safe.util.*;

// Cougaar security services
import org.cougaar.core.security.policy.XMLPolicyCreator;
import org.cougaar.core.security.policy.TypedPolicy;

import com.nai.security.util.DOMWriter;

public class PolicyExpanderPlugin extends SimplePlugin
{
  private boolean debug = true;
  private UnaryPredicate _UCPMPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
	return (o instanceof UnexpandedConditionalPolicyMsg);
      }
    };

  private UnaryPredicate _UPMPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
	return (o instanceof UnexpandedPolicyMsg);
      }
    };

  public void setupSubscriptions()
  {
    _ucpm = (IncrementalSubscription) subscribe(_UCPMPredicate);
    _upm = (IncrementalSubscription) subscribe (_UPMPredicate);
  }

  public void execute()
  {
    // check for added UnexpandedConditionalPolicyMsgs
    Enumeration ucpmEnum = _ucpm.getAddedList();
    while (ucpmEnum.hasMoreElements()) {
      UnexpandedConditionalPolicyMsg ucpm = (UnexpandedConditionalPolicyMsg) ucpmEnum.nextElement();
      // extract the ConditionalPolicyMsg
      ConditionalPolicyMsg condPolicyMsg = ucpm.getConditionalPolicyMsg();
      // get the policies
      Vector policies = condPolicyMsg.getPolicies();
      Vector newPolicies = new Vector();
      // expand each policy
      for (int i=0; i<policies.size(); i++) {
	Msg policy = (Msg) policies.elementAt(i);
	try {
	  Msg realPolicy = (Msg) policy.getSubMsg("Policy");
	  Vector expandedPolicies = expandPolicy (realPolicy);
	  // if the policy was not expanded, keep it in the newPolicies
	  if (expandedPolicies == null) {
	    newPolicies.addElement(policy);
	  }
	  // otherwise, add the expanded policies to the newPolicies
	  else {
	    for (int j=0; j<expandedPolicies.size(); j++) {
	      Msg newPolicy = (Msg) policy.clone();
	      newPolicy.addSubMsg("Policy", (Msg) expandedPolicies.elementAt(j));                        
	      newPolicies.addElement(newPolicy);
	    }
	  }
	}
	catch (Exception xcp) {
	  xcp.printStackTrace();
	  return;
	}                    
      }
      // replace the policies in the condPolicyMsg
      condPolicyMsg.setPolicies(newPolicies);
      publishRemove (ucpm);
      publishAdd (condPolicyMsg);			
    }

    // check for added UnexpandedPolicyMsgs
    Enumeration upmEnum = _upm.getAddedList();
    while (upmEnum.hasMoreElements()) {
      UnexpandedPolicyMsg upm = (UnexpandedPolicyMsg) upmEnum.nextElement();
      PolicyMsg policyMsg = upm.getPolicyMsg();
      Vector domains = policyMsg.getDomains();  // there will only be one domain, but let's pretend.
      for (Iterator itDomain=domains.iterator(); itDomain.hasNext(); ) {
	Msg dMsg = (Msg)itDomain.next();
	String domainName = PolicyMsg.getDomainName(dMsg);

				// Process domain-level policies.
				//
	Vector dPolicies = PolicyMsg.getPolicies(dMsg);
	Vector newDPolicies = new Vector();
	for (int i=0; i<dPolicies.size(); i++) {
	  Msg dPolicyMsg = (Msg) dPolicies.elementAt(i);
	  String policyName = PolicyMsg.getPolicyName(dPolicyMsg);
	  // expand the policy
	  Vector expandedPolicies = expandPolicy(dPolicyMsg);
	  if (expandedPolicies != null) {
	    // remove the original policy
	    policyMsg.removePolicyForDomain(domainName,
					    dPolicyMsg);
	    // add the expanded policies to the new policies vector
	    for (int j=0; j<expandedPolicies.size(); j++) {
	      newDPolicies.addElement(expandedPolicies.elementAt(j));
	    }
	  }
	}   // for each domain policy

				// add the new domain policies to the policyMsg
	for (int i=0 ; i<newDPolicies.size() ; i++) {
	  policyMsg.addPolicyForDomain(domainName,
				       (Msg) newDPolicies.elementAt(i));
	}
	// Get the hosts.
	//
	Vector hosts = PolicyMsg.getHosts(dMsg);
	printDebugString("DomainManager: host count: " + hosts.size(),
			 Logger.LEVEL_MAJOR); 

	for (Iterator itHost=hosts.iterator(); itHost.hasNext(); ) {
	  Msg aHost = (Msg)itHost.next();
	  String hostName = PolicyMsg.getHostName(aHost);
	  // Get the VMs.
	  //
	  Vector VMs = PolicyMsg.getVMs(aHost);
	  printDebugString("DomainManager: VM count: " + VMs.size(), Logger.LEVEL_MAJOR); 
	  for (Iterator itVM=VMs.iterator(); itVM.hasNext(); ) {
	    Msg aVM = (Msg)itVM.next();
	    String vmName = PolicyMsg.getVMName(aVM);
	    // get the VM level policies
	    Vector vmPolicies = PolicyMsg.getPolicies(aVM);
	    Vector newVMPolicies = new Vector();
	    for (int i=0; i<vmPolicies.size(); i++) {
	      Msg vmPolicyMsg = (Msg) vmPolicies.elementAt(i);
	      String policyName = PolicyMsg.getPolicyName(vmPolicyMsg);
	      // expand the policy
	      Vector expandedPolicies = expandPolicy(vmPolicyMsg);
	      if (expandedPolicies != null) {
		// remove the original policy
		policyMsg.removePolicyForVM(domainName,
					    hostName,
					    vmName,
					    vmPolicyMsg);

		// add the expanded policies to the new policies vector
		for (int j=0; j<expandedPolicies.size(); j++) {
		  newVMPolicies.addElement(expandedPolicies.elementAt(j));
		}
	      }
	    }   // for each vm policy

	    // add the new vm policies to the policyMsg
	    for (int i=0; i<newVMPolicies.size(); i++) {
	      policyMsg.addPolicyForVM(domainName,
				       hostName,
				       vmName,
				       (Msg) newVMPolicies.elementAt(i));
	    }
	    // Get the Agents.
	    //
	    Vector agents = PolicyMsg.getAgents(aVM);
	    printDebugString("DomainManager: agent count: "
			     + agents.size(), Logger.LEVEL_MAJOR); 
	    for (Iterator itAgent=agents.iterator(); itAgent.hasNext(); ) {
	      Msg anAgent = (Msg)itAgent.next();
	      String agentName = PolicyMsg.getAgentName(anAgent);
	      String agentID = PolicyMsg.getAgentGUID(anAgent);
	      // Process all the agent's policies.
	      //
	      Vector aPolicies = PolicyMsg.getPolicies(anAgent);
	      printDebugString("DomainManager: policy count for agent " + agentName + 
			       ": " + aPolicies.size(), Logger.LEVEL_MAJOR);
	      Vector newAgentPolicies = new Vector();
	      for (Iterator itAPols=aPolicies.iterator(); itAPols.hasNext(); ) {
		Msg aPolicyMsg = (Msg)itAPols.next();
		String aPolName = PolicyMsg.getPolicyName(aPolicyMsg);
		printDebugString("DomainManager: policy: "
				 + aPolName, Logger.LEVEL_MAJOR);
		// try to expand the policy
		Vector expandedPolicies = expandPolicy(aPolicyMsg);
		if (expandedPolicies != null) {
		  // remove the existing policy since it needs to be replaced
		  // with the expanded policies
		  policyMsg.removePolicyForAgent(domainName,
						 hostName,
						 vmName,
						 agentName,
						 aPolicyMsg);
		  // add the expanded policies to the new policies vector
		  for (int j=0; j<expandedPolicies.size(); j++) {
		    newAgentPolicies.addElement(expandedPolicies.elementAt(j));
		  }
		}								
	      } // agent policies
	      // add the new agent policies to the policy msg
	      for (int i=0; i<newAgentPolicies.size(); i++) {
		policyMsg.addPolicyForAgent(domainName,
					    hostName,
					    vmName,
					    agentName,
					    (Msg) newAgentPolicies.elementAt(i));
	      }							
	    } // agents
	  } // VMs
	} // hosts
      } // domains
      publishRemove (upm);
      publishAdd (new ProposedPolicyMsg(policyMsg));
    }
  }

  /**
   * This function expands a policy
   * 
   * @param policy	Policy message to expand
   * 
   * @return			Vector of policies of type Msg, or null
   *					if the policy was not expanded
   */

  private Vector expandPolicy (Msg policy)
  {
    if (debug == true) {
      System.out.println("Expanding policy message: " + policy);
    }
    try {
      Vector attributes =
	policy.getNamedVector(PolicyConstants.HLP_POLICY_ATTRIBUTES_SYMBOL);
      Vector expandedPolicies = new Vector();
      for (int i=0; i<attributes.size(); i++) {
	Msg attrMsg = (Msg) attributes.elementAt(i);
	if (PolicyMsg.getAttributeName(attrMsg).equals(XML_KEY)) {
	  boolean isSelected = PolicyMsg.getAttributeIsSelected(attrMsg);
	  Document xmlContent = (Document) PolicyMsg.getAttributeValue(attrMsg);
	  XMLPolicyCreator policyCreator =
	    new XMLPolicyCreator(xmlContent, getClusterIdentifier().toAddress());
	  Policy[] policies = policyCreator.getPolicies();
	  if (debug == true) {
	    System.out.println("\n\nTHERE ARE " + policies.length + " POLICIES");
	    //OutputStream os = 
	    //    new FileOutputStream(System.getProperty("org.cougaar.install.path") + "/TEST_XML"); 
	    PrintStream out = new PrintStream(System.out);
	    DOMWriter xmlwriter = new DOMWriter(out);
	    xmlwriter.print(xmlContent);
	  }

	  for (int j=0; j<policies.length; j++) {
	    if (policies[j] instanceof TypedPolicy){
	      TypedPolicy policyObject = (TypedPolicy) policies[j];
	      //System.out.println("policy has: " + policyObject.getRuleParameters().length + " rule parameters");
	      String binderType = policyObject.getType();
	      Msg newPolicy = (Msg) policy.clone();
	      newPolicy.addSymbol(PolicyConstants.
				  HLP_POLICY_TYPE,
				  binderType);                     
	      PolicyMsg.setPolicyMsgAttribute(newPolicy,
					      org.cougaar.core.security.policy.TypedPolicy.POLICY_OBJECT_KEY,
					      policyObject,
					      isSelected);
	      expandedPolicies.addElement(newPolicy);
	      if (debug == true) {
		System.out.println("Adding policy object["+ i + "]: " +
				   binderType + " - " + attributes.elementAt(i));
	      }
	    }
	  }                   
	}
      }

      if (expandedPolicies.size() > 0) {
	return expandedPolicies;
      }            
    }
    catch (Exception xcp) {
      xcp.printStackTrace();
    }
    return null;
  }
  public void printDebugString (String s, int n) {
    System.out.println(s);
  }

  private IncrementalSubscription _ucpm;
  private IncrementalSubscription _upm;

  public static final String XML_KEY = "XMLContent";
  //public static final String POLICY_OBJECT_KEY = "POLICY_OBJECT";

}

