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



package org.cougaar.core.security.policy;

import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import kaos.core.util.ConditionalPolicyMsg;
import kaos.core.util.PolicyMsg;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import safe.util.ProposedPolicyUpdate;
import safe.util.UnexpandedConditionalPolicyMsg;
import safe.util.UnexpandedPolicyUpdate;

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

