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

package com.nai.security.test;

import java.util.*;
import com.nai.security.policy.GuardRegistration;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.planning.ldm.policy.RuleParameter;
import SAFE.Enforcer.NodeEnforcer;  // or import SAFE.Enforcer.AgentEnforcer;

public class DummyGuardRegistration extends GuardRegistration implements NodeEnforcer {
  public DummyGuardRegistration(String aPolicyType, String enforcerName) {
    super(aPolicyType, enforcerName);
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
    System.out.println("DummyGuardRegistration: " + policy);
    RuleParameter[] param = policy.getRuleParameters();
    for (int i = 0 ; i < param.length ; i++) {
      System.out.println("Rule: " + param[i].getName() + " - " + param[i].getValue());
    }
  }
}
