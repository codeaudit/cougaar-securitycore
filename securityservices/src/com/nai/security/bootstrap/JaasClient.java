/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package com.nai.security.bootstrap;

import java.security.Principal;

import java.util.Iterator;
import java.security.PrivilegedAction;
import java.security.AccessController;
import java.security.AccessControlContext;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

public class JaasClient {
  private static int debug = 0;

  static {
    String s = System.getProperty("org.cougaar.core.security.jaasDebug");
    if ("true".equals(s)) {
      debug = 1;
    }
  }

  /**
   *  The doAs method should be called by any core component that wishes to run
   *  another component in a specific access controller context.
   *  This provides several advantages:
   *    1) A policy may be associated with a particular instance of
   *       a component.
   *    2) Instance information can be retrieved by the Security Manager
   *       when the contained component does not comply with the policy.
   *
   *  Here's an example of how the method should be called:
   *
   *   OR:
   *
   *  obj = JaasClient.doAs(agentName, new java.security.PrivilegedAction() {
   *	public Object run() {
   *	  Object o;
   *	  // Do action here
   *	  return o;
   *	}
   *   });
   */
  public Object doAs(String agentName,
		     java.security.PrivilegedAction action) {
    Subject subj = createSubject(agentName);
    return doAs(subj, action);
  }

  /**
   * Same method except that the privilege action can return
   * an exception. Below is an example of how it could be called:
   *
   *  try {
   *    obj = JaasClient.doAs(agentName,
   *                          new java.security.PrivilegedExceptionAction() {
   *	 public Object run() throws Exception {
   *	   Object o;
   *	   // Do action here
   *	   return o;
   *	 }
   *     });
   *  } catch (Exception e) {
   *  }
   */
  public Object doAs(String agentName,
		     java.security.PrivilegedExceptionAction action)
    throws Exception {
    Subject subj = createSubject(agentName);
    return doAs(subj, action);
  }

  /** Print the list of principals associated with the running
   *  context.
   */
  public static void printPrincipals() {
    final AccessControlContext acc = AccessController.getContext();
    Subject subj = (Subject)
      AccessController.doPrivileged(new PrivilegedAction() {
	  public Object run() {
	    Subject subj = Subject.getSubject(acc);
	    return subj;
	  }
	});
    if (subj != null) {
      Iterator it = subj.getPrincipals().iterator(); 
      while (it.hasNext()) {
	System.out.println(it.next());
      }
    }
  }

  private void addChainedPrincipal(Subject subject, Principal newPrincipal)
  {
    if (subject == null) {
      throw new IllegalArgumentException("Subject cannot be null");
    }

    ChainedPrincipal  cp = new ChainedPrincipal();

    // Find out if there is a chained principal in the current
    // security context.
    final AccessControlContext acc = AccessController.getContext();

    Subject subj = (Subject)
      AccessController.doPrivileged(new PrivilegedAction() {
	  public Object run() {
	    Subject subj = Subject.getSubject(acc);
	    return subj;
	  }
	});
    
    if (subj != null) {
      Iterator it = subj.getPrincipals().iterator(); 
      Principal p = null;
      while (it.hasNext()) {
	p = (Principal) it.next();
	if (p instanceof ChainedPrincipal) {
	  cp.addChainedPrincipals(((ChainedPrincipal)p).getChain());
	  break;
	}
      }
    }
    cp.addPrincipal(newPrincipal);
    subject.getPrincipals().add(cp);
  }

  private Subject createSubject(String name) {
    final Subject s = new Subject();

    /* Adding the cluster identifier string as a principal
     * We could also add certificate credentials at this point.
     */
    Principal namePrincipal = new StringPrincipal(name);
    s.getPrincipals().add(namePrincipal);

    addChainedPrincipal(s, namePrincipal);

    /* Modifications (additions and removals) to this Subject's Principal
     * Set and credential Sets will be disallowed. The destroy operation
     * on this Subject's credentials will still be permitted. 
     */
    AccessController.doPrivileged(new PrivilegedAction() {
	public Object run() {
	  s.setReadOnly();
	  return null; // nothing to return
	}
      });
    return s;
  }

  private Object doAs(Subject subj, java.security.PrivilegedAction action) {
    Object o = null;
    if (debug > 0) {
      System.out.print("Principals: ");
      Iterator it = subj.getPrincipals().iterator(); 
      while (it.hasNext()) 
        System.out.print(it.next() + ". ");
      System.out.println("");
    }
    
    /* 1- Retrieve the current Thread's AccessControlContext via
     *    AccessController.getContext
     * 2- Instantiates a new AccessControlContext using the retrieved
     *    context along with a new SubjectDomainCombiner (constructed
     *    using the provided Subject).
     * 3- Finally, invoke AccessController.doPrivileged, passing it
     *    the provided PrivilegedAction, as well as the newly
     * constructed AccessControlContext. 
     */
    if (debug > 0) {
      System.out.println("JaasClient. Calling doAs ");
    }
    o = Subject.doAs(subj, action);
    if (debug > 0) {
      System.out.println("JaasClient. doAs done ");
    }
    return o;
  }

  private Object doAs(Subject subj,
		     java.security.PrivilegedExceptionAction action)
    throws Exception {
    Object o = null;

    if (debug > 0) {
      System.out.println("Login assigned these principals: ");
      Iterator it = subj.getPrincipals().iterator(); 
      while (it.hasNext()) 
        System.out.println("\t" + it.next());
    }
    
    /* 1- Retrieve the current Thread's AccessControlContext via
     *    AccessController.getContext
     * 2- Instantiates a new AccessControlContext using the retrieved
     *    context along with a new SubjectDomainCombiner (constructed
     *    using the provided Subject).
     * 3- Finally, invoke AccessController.doPrivileged, passing it
     *    the provided PrivilegedAction, as well as the newly
     * constructed AccessControlContext.
     */
    if (debug > 0) {
      System.out.println("JaasClient. Calling doAs ");
    }
    o = Subject.doAs(subj, action);
    if (debug > 0) {
      System.out.println("JaasClient. doAs done ");
    }
    return o;
  }

}
