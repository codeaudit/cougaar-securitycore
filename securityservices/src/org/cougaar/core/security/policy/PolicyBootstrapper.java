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

import org.cougaar.domain.planning.ldm.policy.Policy;

import org.cougaar.util.ConfigFinder;

public class PolicyBootstrapper {

  XMLPolicyCreator xpc;
  static private boolean debug = false;

  static String PolicyPath = System.getProperty("org.cougaar.core.security.BootPolicy", "BootPolicy.ldm.xml");
  
  public PolicyBootstrapper(){
    debug = System.getProperty("org.cougaar.core.security.policy.debug", "false").equalsIgnoreCase("true");
    xpc = new XMLPolicyCreator(PolicyPath, new ConfigFinder(), "PolicyBootstrapper");
  }
  
  public Policy[] getBootPolicy(String type){
    if (debug) {
      System.out.println("getBootPolicy: " + type);
    }
    if(xpc!=null) return xpc.getPoliciesByType(type);
    return null;
  }
}
