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

package com.nai.security.test;

import java.util.Iterator;
import java.security.PrivilegedAction;
import java.security.AccessController;
import java.security.AccessControlContext;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

import com.nai.security.bootstrap.JaasClient;
import com.nai.security.bootstrap.CougaarSecurityManager;

public class TestJaas {
  public static void main(String args[]) {
    System.out.println("TestJaas main()");
    String agentName = "3ID-HHC";
    DummyAgent agent = null;

    // Set security manager
    System.setSecurityManager(new CougaarSecurityManager());

    try {
      agent = (DummyAgent) JaasClient.doAs(agentName, new java.security.PrivilegedExceptionAction() {
	  public Object run() throws Exception {
	    DummyAgent agent = new DummyAgent();
	    System.out.println("In TestJaas.doAs(run). Calling printSubject()");
	    printSubject();
	    agent.run();
	    return (Object) agent;
	  }
	});
    }
    catch (Exception e) {
      e.printStackTrace();
    }
    System.out.println("TestJaas. Done");
  }

  public static void printSubject() {
    AccessControlContext acc = AccessController.getContext();
    Subject subj = Subject.getSubject(acc);
    System.out.println("  TestJaas. printSubject():");
    if (subj != null) {
      Iterator it = subj.getPrincipals().iterator(); 
      while (it.hasNext()) {
	System.out.println("  <principal>" + it.next() + "</principal>");
      }
    }
  }
}

