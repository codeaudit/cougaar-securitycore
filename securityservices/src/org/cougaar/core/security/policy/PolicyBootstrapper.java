/**
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 *
 * Created on September 19, 2001, 2:38 PM
 */

package org.cougaar.core.security.policy;

import java.util.Properties;
import java.io.File;

// Cougaar core services
import org.cougaar.util.ConfigFinder;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.PolicyBootstrapperService;
import org.cougaar.core.security.config.ConfigParserServiceImpl;

//from kaos
import kaos.core.util.PolicyMsg;
import kaos.core.util.AttributeMsg;

public class PolicyBootstrapper 
  implements PolicyBootstrapperService
{

  private ServiceBroker serviceBroker;
  private ConfigParserService cps;
  private boolean debug = false;

  static String PolicyPath =
    System.getProperty("org.cougaar.core.security.BootPolicy",
		       "BootPolicy.ldm.xml");
  
  public PolicyBootstrapper(ServiceBroker sb) {
    serviceBroker = sb;
    debug = System.getProperty("org.cougaar.core.security.policy.debug",
			       "false").equalsIgnoreCase("true");

    if (debug) {
      System.out.println("Initializing Policy bootstrapper");
    }

    cps = (ConfigParserService)
      serviceBroker.getService(this,
			       ConfigParserService.class,null);
    
    //absolutely required.
    if (cps == null)
      throw new RuntimeException("PolicyBootstrapper failed to get ConfigParserService.");
  }
  
  public PolicyMsg getBootPolicy(Class type)
  {
    if (debug) {
      System.out.println("getBootPolicy: " + type);
    }
    SecurityPolicy[] policies = cps.getSecurityPolicies(type);
    
    PolicyMsg policyMsg = null;
    if (policies != null) {
        policyMsg = new PolicyMsg ("",
                                             "",
                                             "",
                                             "",
                                             "",
                                             "",
                                             "",
                                             "",
                                             "",
                                             true,
                                             false,
                                             false);
        for (int i=0; i<policies.length; i++) {                    
            // wrap the policy in a KAoS message
            AttributeMsg attribMsg = new AttributeMsg("POLICY_OBJECT",
                                                      policies[i],
                                                      true);
            policyMsg.setAttribute(attribMsg);
        }
    } 
    return policyMsg;
  }
}
