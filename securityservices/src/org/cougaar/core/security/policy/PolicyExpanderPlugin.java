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

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Vector;
import java.util.Iterator;
import java.util.List;
import java.io.*;

import org.w3c.dom.Document;

// Core Cougaar
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.planning.ldm.policy.Policy;

// KAoS policy management
import kaos.policy.util.PolicyConstants;
import kaos.core.util.*;
import safe.util.*;

// Cougaar security services
import org.cougaar.core.security.policy.XMLPolicyCreator;
import org.cougaar.core.security.policy.TypedPolicy;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.util.DOMWriter;

/**
 * The PolicyExpanderPlugIn expands policies before
 * they reach the DomainManagerPlugIn for approval.
 * 
 * It subscribes to UnexpandedPolicyUpdates and
 * UnexpandedConditionalPolicyMsgs.
 * 
 * It publishes ConditionalPolicyMsgs and ProposedPolicyUpdates.
 * 
 * The actual policy expansion happens in the expandPolicy function. Please see
 * the comments for that method for details on how to expand policies.
 */
public class PolicyExpanderPlugin
  extends ComponentPlugin
{
  private SecurityPropertiesService secprop = null;
  private LoggingService log;

  private UnaryPredicate _unexCondPolicyPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        return (o instanceof UnexpandedConditionalPolicyMsg);
      }
    };
  private UnaryPredicate _unexPolicyUpdatePredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        return (o instanceof UnexpandedPolicyUpdate);
      }
    };

  protected void setupSubscriptions() {
    secprop = (SecurityPropertiesService)
      getBindingSite().getServiceBroker().getService(this,
						     SecurityPropertiesService.class, null);

    log = (LoggingService)
      getBindingSite().getServiceBroker().getService(this,
						     LoggingService.class, null);

    _ucpm = (IncrementalSubscription) blackboard.subscribe(_unexCondPolicyPredicate);
    _upu = (IncrementalSubscription) blackboard.subscribe (_unexPolicyUpdatePredicate);
  }
    
  protected void execute()
    {
      if (log.isDebugEnabled()) log.debug("PolicyExpanderPlugIn::execute()");
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
	  PolicyMsg policyMsg = (PolicyMsg) policies.elementAt(i);
	  try {                    
	    expandPolicy (policyMsg);
	  }
	  catch (Exception xcp) {
	    xcp.printStackTrace();
	  }                    
	}
	blackboard.publishRemove (ucpm);
	if (log.isDebugEnabled()) log.debug("publishAdd ConditionalPolicyMsg");
	blackboard.publishAdd (condPolicyMsg);			
      }
        
      // check for added UnexpandedPolicyUpdates
      Enumeration upuEnum = _upu.getAddedList();
      while (upuEnum.hasMoreElements()) {
	UnexpandedPolicyUpdate upu = (UnexpandedPolicyUpdate) upuEnum.nextElement();
	expandListedPolicies(upu._addedPolicies);
        expandListedPolicies(upu._changedPolicies);
        expandListedPolicies(upu._removedPolicies);
	blackboard.publishRemove (upu);
	blackboard.publishAdd (new ProposedPolicyUpdate(upu._addedPolicies,
                                                        upu._changedPolicies,
                                                        upu._removedPolicies));
      }
    }

  private void expandListedPolicies(List policies)
  {
    Iterator policyIt = policies.iterator();
    while (policyIt.hasNext()) {
      PolicyMsg policyMsg = (PolicyMsg) policyIt.next();
      try {
        expandPolicy (policyMsg);
      }
      catch (Exception xcp) {
        xcp.printStackTrace();
      }
    }
  }

  /**
   * This function expands a policy
   * 
   * The original policy should be kept intact, in that no existing fields
   * are removed or changed. You should expand the policy by
   * adding to the original. You may add new attributes, or add new key-value
   * pairs, or add sub-messages to the original policy, whichever way you
   * prefer, as long as the enforcers can parse the additions. The current
   * KAoS infrastructure does not parse these additions so no restrictions
   * are placed on the types of things you add to the original policy.
   * 
   * @param policy	Policy message to expand
   */
  private void expandPolicy(PolicyMsg policyMsg)
    throws Exception
    {
      if (log.isDebugEnabled()) {
	log.debug("Expanding policy message: " + policyMsg);
      }

/***---doesn't seem necessary at this point
      Document xmlContent = null;
      for (int i=0; i<attributes.size(); i++) {
	AttributeMsg attrMsg = (AttributeMsg) attributes.elementAt(i);

	// Find the XML policy attributes and expand them
	if (attrMsg.getName().equals(XML_KEY)) {
	  xmlContent = (Document) attrMsg.getValue();

	  XMLPolicyCreator policyCreator =
	    new XMLPolicyCreator(xmlContent, getMessageAddress().toAddress());
	  Policy[] policies = policyCreator.getPolicies();

	  if (log.isDebugEnabled()) {
	    log.debug("\n\nTHERE ARE " + policies.length
			       + " POLICIES");
	    PrintStream out = new PrintStream(System.out);
	    DOMWriter xmlwriter = new DOMWriter(out);
	    xmlwriter.print(xmlContent);
	  }

	  for (int j = 0 ; j < policies.length ; j++) {
	    if (policies[j] instanceof TypedPolicy){
	      TypedPolicy policyObject = (TypedPolicy) policies[j];
	      // Add policy type.
	      String binderType = policyObject.getType();
	      policyMsg.addSymbol(PolicyConstants.HLP_POLICY_TYPE,
				  binderType);

	      policyMsg.addSymbol(org.cougaar.core.security.
				  policy.TypedPolicy.POLICY_OBJECT_KEY,
				  policyObject);
	      if (log.isDebugEnabled()) {
		log.debug("Adding policy object["+ i + "]: " +
				   binderType + " - " + policyObject);
	      }
	    }
	  }                   
	}
      }
*/    }
  private IncrementalSubscription _ucpm;
  private IncrementalSubscription _upu;
  
  public static final String XML_KEY = "XMLContent";

}

