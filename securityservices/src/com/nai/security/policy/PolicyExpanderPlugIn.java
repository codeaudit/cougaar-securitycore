package com.nai.security.policy;

import org.cougaar.core.plugin.SimplePlugIn;
import org.cougaar.core.cluster.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.w3c.dom.Document;
import org.cougaar.domain.planning.ldm.policy.Policy;
import org.cougaar.core.security.policy.XMLPolicyCreator;
import org.cougaar.core.security.policy.TypedPolicy;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Vector;
import java.util.Iterator;

import KAoS.Util.Msg;
import KAoS.Policy.PolicyConstants;
import KAoS.KPAT.message.PolicyMsg;
import KAoS.Util.Logger;
import SAFE.Util.*;
	
public class PolicyExpanderPlugIn extends SimplePlugIn
{
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
	Vector expandedPolicies = expandPolicy (policy);
				// if the policy was not expanded, keep it in the newPolicies
	if (expandedPolicies == null) {
	  newPolicies.addElement(policy);
	}
				// otherwise, add the expanded policies to the newPolicies
	else {
	  for (int j=0; j<expandedPolicies.size(); j++) {
	    newPolicies.addElement(expandedPolicies.elementAt(j));
	  }
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
      System.out.println("PolicyExpanderPlugIn: expanding policy message");
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
	for (int i=0; i<newDPolicies.size(); i++) {
	  policyMsg.addPolicyForDomain(domainName,
				       (Msg) newDPolicies.elementAt(i));
	}

				// Get the hosts.
				//
	Vector hosts = PolicyMsg.getHosts(dMsg);
	printDebugString("DomainManager: host count: " + hosts.size(), Logger.LEVEL_MAJOR); 
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
	    printDebugString("DomainManager: agent count: " + agents.size(), Logger.LEVEL_MAJOR); 
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
		printDebugString("DomainManager: policy: " + aPolName, Logger.LEVEL_MAJOR);

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
      System.out.println("PolicyExpanderPlugIn: publishing ProposedPolicyMessage");
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
    try {
      HashMap attributes = (HashMap) policy.getSymbol(PolicyConstants.HLP_POLICY_ATTRIBUTES_SYMBOL);
      if (!attributes.containsKey(XML_KEY)) {
				// this policy message contains no XML content, so
				// don't expand it
	return null;
      }
      else {
	Vector expandedPolicies = new Vector();
				// remove the xml content from the attribute table
	Document xmlContent = (Document) attributes.remove(XML_KEY);
				// create a copy of the original message

	XMLPolicyCreator policyCreator = new XMLPolicyCreator(xmlContent);
	Policy[] policies = policyCreator.getPolicies();
	if (policies == null) {
	  return expandedPolicies;
	}
	for (int i=0; i<policies.length; i++) {
	  if (policies[i] instanceof TypedPolicy){
	    Msg policy1 = (Msg) policy.clone();
	    // create a copy of the attribute table
	    HashMap attributes1 = (HashMap) attributes.clone();						
	    String binderType = ((TypedPolicy)policies[i]).getType();
	    // put the policy object into the attribute table
	    attributes1.put(POLICY_OBJECT_KEY, policies[i]);
	    // put the updated table into the cloned message
	    policy1.addSymbol(PolicyConstants.HLP_POLICY_ATTRIBUTES_SYMBOL,
			      attributes1);
	    // set the binder type of the message
	    policy1.addSymbol("PolicyType", binderType);
	    // add the message to the expanded policy messages
	    expandedPolicies.addElement(policy1);
	  }
	}
				
	return expandedPolicies;		
      }
    }	
    catch (Exception xcp) {
      xcp.printStackTrace();
      return null;
    }
  }
	
	
  public void printDebugString (String s, int n) {
    System.out.println(s);
  }
	
  private IncrementalSubscription _ucpm;
  private IncrementalSubscription _upm;

  private XMLPolicyCreator xmlPolicyCreator;
	
  public static final String XML_KEY = "XMLContent";
  public static final String POLICY_OBJECT_KEY = "NAI_POLICY_OBJECT";
}
