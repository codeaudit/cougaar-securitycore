/*
 * <copyright>
 *  Copyright 2001 Networks Associates Technology, Inc.
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

package org.cougaar.core.security.test.jaas;

import org.cougaar.core.security.auth.JaasClient;

/** A simple simulation of a node with JAAS security contexts.
 *  The node starts the agents in their own security context.
 */
public class Node {
  public static void main(String args[]) {
    System.out.println("TestJaas main()");

    Node node = new Node();
    String agentName1 = "3ID-HHC";
    String agentName2 = "NCA";
    Agent agent = null;

    try {
      // Start agentName1 in its own security context
      agent = node.launchAgent(agentName1);
    }
    catch (Exception e) {
      e.printStackTrace();
    }
  }

  private Agent launchAgent(final String agentName)
  {
    Agent agent = null;
    JaasClient jc = new JaasClient();
    try {
      System.out.println("Agent Manager starting "
			 + agentName);
      agent = (Agent)
	jc.doAs(agentName,
		new java.security.PrivilegedExceptionAction() {
		    public Object run() throws Exception {
		      Agent agent = new Agent(agentName);
		      System.out.println("  Agent manager: "
					 + agentName
					 + " security context is:");
		      JaasClient.printPrincipals();
		      agent.execute();
		      return (Object) agent;
		    }
		  }, true);
    }
    catch (Exception e) {
      e.printStackTrace();
    }
    return agent;
  }
}

