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
