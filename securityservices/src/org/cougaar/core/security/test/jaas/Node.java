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

