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

import java.util.Hashtable;

import kaos.policy.enforcement.Enforcer;
import kaos.policy.guard.Guard;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.planning.ldm.policy.KeyRuleParameter;
import org.cougaar.planning.ldm.policy.KeyRuleParameterEntry;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.planning.ldm.policy.RangeRuleParameter;
import org.cougaar.planning.ldm.policy.RangeRuleParameterEntry;
import org.cougaar.planning.ldm.policy.RuleParameter;

/**
 * Parent class, which defines methods for processing Cougaar and KAoS 
 * policies. Conforming to Cougaar conventions the default rule key is the
 * String "DEFAULT". If the property org.cougaar.core.security.policy.debug is
 * set "True" the verbse messaging will be printed to standard output.
 * <I>Note: PolicyRuleBean is used as a data structure instead of 
 * RuleParameter to avoid policy expansion at EVERY query. </I>
 * @version 1.1
 * @author Anya Figlin
 * @author Jay Jacobs
 */
public class PolicyCache
  extends GuardRegistration
  implements Enforcer
{
  /**
   * toggles debugging messages for a vebose mode
   */
  protected boolean debug = false;

  /**
   * An instance of a rule bean, used as an optimization. Do not expect
   * any usable values unless you explicitly make an assignment. It is not
   * guaranteed to be non-null!!
   */
  protected PolicyRuleBean rule;

  /**
   * A cache of <CODE>PolicyRuleBean</CODE> values.
   */
  protected Hashtable cache = new Hashtable();
    
  /**
   * Key to use for denoting default policy 
   */
  public static final String DEFAULT = "DEFAULT";

  /** The KAoS guard **/
  private Guard guard;

  /**
   * Constructor registers as KAoS binder and sets default variables based 
   * on system properties.
   * <P>This constructor tests for the following system properties:
   * <UL>
   *   <LI> org.cougaar.core.security.policy.debug
   * </UL>
   */
  public PolicyCache(String type, String enforcerName, ServiceBroker sb) 
  {
    super(type, enforcerName, sb);	// GuardRegistration constructor...
    if(debug)log.debug("new PolicyCache for type " + type);
    try {
      registerEnforcer();
    }
    catch(Exception ex) {
      if(debug) {
	log.debug("PolicyCache: registration exception");
	if(debug)ex.printStackTrace();
      }
    }
  }

  /**
   * Convenience method for generic rule parameters with a default key 
   */
  protected void createPolicyRuleBean(RuleParameter rule) 
  {
    createPolicyRuleBean(rule.getName(), DEFAULT, rule.getValue());
  }

  /**
   * Creates a new policy rule bean and then add the new bean into the cache
   */
  protected void createPolicyRuleBean(String name, String key, Object value)
  {
    rule = new PolicyRuleBean(name, key, value);
    cache.put((Object)name, rule);
    if(debug) {
      log.debug("PolicyCache: added to cache - " + rule);
    }
  }


  /**
   * Default method for processing a policy rule bean. Key value is set to
   * DEFAULT, and name and value are taken from the rule parameter. 
   * Unsupported classes listed below may reuire new methods for correct
   * processing.
   * <P>Currently unsupported <CODE>RuleParameter</CODE> subclasses include:
   * <UL> 
   *   <LI> EnumerationRuleParameter
   *   <LI> BooleanRuleParameter
   *   <LI> ClassRuleParameter
   *   <LI> DoubleRuleParameter
   *   <LI> PredicateRuleParameter
   *   <LI> LongRuleParameter
   * </UL> 
   */
  protected void createPolicyRuleBeans(RuleParameter rule) {
    createPolicyRuleBean(rule);
  }

  /**
   * Creates a rule bean for each entry in the parameter and a default
   * rules if one is specified.
   */
  protected void createPolicyRuleBeans(KeyRuleParameter krp) {
    if(debug) {
      log.debug("PolicyCache: processing KeyRuleParameter");
    }
    // if the key rule parameter has a non-null value
    if(krp.getValue()!= null && !((String)krp.getValue()).equals("")) {
      // create a new rule bean and add it to the cache
      createPolicyRuleBean(krp);
    }
    // add rule beans for each of the keys in this rule parameter
    createPolicyRuleBeans(krp.getName(), krp.getKeys());
  }
    
  /**
   * Creates a rule for each key rule parameter entry.
   */
  protected void createPolicyRuleBeans(String name,
				       KeyRuleParameterEntry[] entry) {
    if(debug) {
      log.debug("PolicyCache: processing KeyRuleParamEntry");
    }
    for(int i = 0; i < entry.length; i++) {
      createPolicyRuleBean(name, entry[i].getKey(), 
			   entry[i].getValue());
    }
  }
  /**
   * Creates a default and then processes the ranges of this rule.
   */
  protected void createPolicyRuleBeans(RangeRuleParameter rrp){
    if(debug) {
      log.debug("PolicyCache: processing RangeRuleParameter");
    }
    //if default value exists...
    if (rrp.getValue()!= null && !((String)rrp.getValue()).equals("")) {
      createPolicyRuleBean(rrp);
    }
    createPolicyRuleBeans(rrp.getRanges());
  }

  /**
   * Creates a rule bean for each range rule parameter entry.
   */
  protected void createPolicyRuleBeans(RangeRuleParameterEntry[] entries)
  {
    RangeRuleParameterEntry range = null; 
    if(debug) {
      log.debug("PolicyCache: processing RangeRuleParamEntry");
    }
    for (int i=0; i < entries.length; i++) {
      range = entries[i];
      Object value = range.getValue();
      if(value instanceof KeyRuleParameter)
	createPolicyRuleBeans((KeyRuleParameter)value);
      else if(value instanceof RuleParameter)
	createPolicyRuleBeans((RuleParameter)value);
      else 
	log.debug("PolicyCache: Range value isn't rule!");
    }
  }

  /**
   * Generic rule for getting a rule value from the cache 
   * @param name a name value, used as unique key
   * @return a policy rule bean which match the specified name
   */
  public PolicyRuleBean get(String name) { 
    return (PolicyRuleBean)cache.get((Object)name); 
  }

  /**
   * Message to tel if the cache has received any policy.
   * @return true if the cache is empty, otherwise false.
   */
  public boolean isEmpty() 
  {
    return cache.isEmpty();
  }

  /**
   * Merges an existing policy with a new policy.
   * @param policy the new policy to be added
   */
  public void receivePolicyMessage(Policy policy) {
    if(policy == null)return;
    RuleParameter[] ruleParameters = policy.getRuleParameters();
    //for each RuleParameter
    for (int j=0; j < ruleParameters.length; j++)
      createPolicyRuleBeans(ruleParameters[j]);
  }

  public void receivePolicyMessage(Policy policy,
				   String policyID,
				   String policyName,
				   String policyDescription,
				   String policyScope,
				   String policySubjectID,
				   String policySubjectName,
				   String policyTargetID,
				   String policyTargetName,
				   String policyType) {
    if (debug) {
      log.debug("PolicyCache.receivePolicyMessage");
    }
    if(policy == null)return;
    RuleParameter[] ruleParameters = policy.getRuleParameters();
    //for each RuleParameter
    for (int j=0; j < ruleParameters.length; j++)
      createPolicyRuleBeans(ruleParameters[j]);
  }
    

} // End class PolicyCache
