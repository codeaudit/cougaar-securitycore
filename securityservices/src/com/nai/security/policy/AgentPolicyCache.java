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

import org.cougaar.domain.planning.ldm.policy.Policy;
import SAFE.Enforcer.AgentEnforcer;
import KAoS.Util.Msg;

public class AgentPolicyCache extends PolicyCache implements AgentEnforcer {

  private String agent;
    
  public AgentPolicyCache(String type, String name)
  {
    super(type, name);
    agent = name;
  }

  /**
   * Accessor method for the human-=readable agent name.
   */
  public String getAgentName() { return agent; }

  /**
   * Accessor method for the (unique) identifier of the agent. Currently,
   * this is the same as an agent's name, but may change in the future.
   */
  public String getAgentId() { return agent; }

  /**
   * If this policy is an agent level polcicy and the agent name matches 
   * subject name, then receive the new policy.
   */
  public void receivePolicyMessage(Policy policy,
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
    if(policyScope.equalsIgnoreCase("Agent")) 
      if(policySubjectID.equals(getAgentId()))
	receivePolicyMessage(policy);
  }
    
}




