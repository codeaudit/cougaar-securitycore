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
import org.cougaar.core.cluster.*;
import com.nai.security.access.*;
import org.cougaar.domain.planning.ldm.policy.*;
import org.cougaar.util.*;


public class MTSPolicyCache extends AgentPolicyCache 
    implements PolicyCacheServesProxy
{
    /**
     * Destination for messages that are set aside
     */
    public String newMessageDestination = "";


    /**
     * Default constructor for creating a message transport service policy
     * cache. The security aware message transport service proxy should listen
     * for  access control policy for a specific agent.
     */

    public MTSPolicyCache(String name) 
    {
	super("com.nai.security.policy.AccessControlPolicy", name);
    }

    // Policy-related methods

    /**
     * Accessor for major index of lookup table.
     * @return the minor index, which is searchable by key
     */
    protected Hashtable getSection(Object key)
    {
	Object section = cache.get(key);
	Hashtable minor;
	if(section instanceof Hashtable)
	    return (Hashtable)section;
	minor = new Hashtable(1);
	cache.put(key, minor);
	if(section instanceof PolicyRuleBean) {
	    PolicyRuleBean bean = (PolicyRuleBean)section;
	    minor.put(bean.getKey(), bean);
	} 
	return minor;
	
    }

    /**
     * Convenieniece method for parsing rule parameters into policy rule beans
     * which are fully expanded policy atoms. The bean value can be String,
     * String[], or TrustAttribute instances.
     */
    protected void createPolicyRuleBean(String name, String key, Object value)
    {
	String action[] = new String[2];
	String data = (String)value;
	rule = new PolicyRuleBean(name, key, value);
	//cache.addElement(rule);  // add it to vector for logging purposes
	// replace these else-if's with a trust attribute factory
	if(name.equals(AccessControlPolicy.IN_MSG_CRITICALITY))
	    value = (Object)new MissionCriticality(data);
	else if(name.equals(AccessControlPolicy.OUT_MSG_CRITICALITY))
	    value = (Object)new MissionCriticality(data);
	else if(name.equals(AccessControlPolicy.IN_MSG_INTEGRITY))
	    value = (Object)new MissionCriticality(data);
	else if(name.equals(AccessControlPolicy.OUT_MSG_INTEGRITY))
	    value = (Object)new MissionCriticality(data);
	else if(name.equals(AccessControlPolicy.IN_MSG_ACTION)) {
	    StringTokenizer tok = new StringTokenizer((String)value, ":");
	    action[0] = tok.nextToken();
	    if(action[0].equals(AccessControlPolicy.FORWARD)) {
		action[1] = tok.nextToken();
		value = action;
	    }
	    else {
		value = action[0];
	    }
	}
	put(rule);
	if(debug) {
	    System.out.println("PolicyCache: added to cache - " + rule);
	}	
    }

    /**
     * Add a new policy rule into the cache.
     */
    protected void put(PolicyRuleBean bean) 
    {
	Hashtable section = getSection((Object)bean.getName());
	section.put((Object)bean.getKey(), (Object)bean); 
    }

    /**
     * Fetch a policy rule by name and key. Key value may possibly be null.
     * @return a policy rule bean or null if not found.
     */
    public PolicyRuleBean get(String name, String key) 
    {				
	Hashtable section = getSection((Object)name);
	Object value = section.get((Object)key);
	if(value == null)	// check for default value if first get fails
	    value = section.get((Object)AccessControlPolicy.DEFAULT);
	return (PolicyRuleBean)value;
    }

    /**
     * Message to tel if the cache has received any policy.
     * @return true if the cache is empty, otherwise false.
     */
    public boolean isEmpty() 
    {
	return cache.isEmpty();
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
       if(policyType.equals(getPolicyType()))
	 super.receivePolicyMessage(policy, policyID, policyName,
	   policyDescription,  policyScope, policySubjectID,
	   policySubjectName, policyTargetID, policyTargetName, policyType); 
  }

    
} // end class MTSPolicyCache














