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

public class Agent
{
  String name = null;
  public Agent(String aName) {
    name = aName;
  }

  public Object execute() {
    launchPlugin("LDM");
    return null;
  }

  private Plugin launchPlugin(final String plugInName)
  {
    Plugin plugin = null;
    JaasClient jc = new JaasClient();
    try {
      System.out.println("Launching plugin "
			 + plugInName);
      plugin = (Plugin)
	jc.doAs(plugInName,
		new java.security.PrivilegedExceptionAction() {
		    public Object run() throws Exception {
		      Plugin plugin = new Plugin(plugInName);
		      System.out.println("Agent : "
					 + plugInName
					 + " security context is:");
		      JaasClient.printPrincipals();
		      plugin.execute();
		      return (Object) plugin;
		    }
		  }, true);
    }
    catch (Exception e) {
      System.out.println("Exception occuring while executing Plugin: " + e);
    }
    return plugin;
  }
}
