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

// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.planning.ldm.policy.Policy;

import safe.enforcer.AgentEnforcer;

public class AgentPolicyCache extends PolicyCache implements AgentEnforcer {

  private String agent;
    
  public AgentPolicyCache(String type, String name, ServiceBroker sb)
  {
    super(type, name, sb);
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




