/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

package org.cougaar.core.security.auth;

import java.security.Principal;

import java.util.Iterator;
import java.security.PrivilegedAction;
import java.security.AccessController;
import java.security.AccessControlContext;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.io.CharArrayWriter;
import java.io.PrintWriter;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class JaasClient {
  private ExecutionContext _context;
  private static Logger _log;
  
  public JaasClient() {
    if (_log == null) {
      _log = LoggerFactory.getInstance().createLogger(this);
    }
    if (_log == null) {
      throw new RuntimeException("Unable to get LoggingService");
    }
  }
  
  public JaasClient(ExecutionContext context) {
    this();
    _context = context; 
  }
  
  public Object doAs(ExecutionContext ec, 
    java.security.PrivilegedAction action, boolean displaySubject) {
  
    Subject subj = createSubject(ec);
    return doAs(subj, action, displaySubject);  
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
		     java.security.PrivilegedAction action, boolean displaySubject) {
    Subject subj = createSubject(agentName);
    return doAs(subj, action, displaySubject);
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
		     java.security.PrivilegedExceptionAction action, boolean displaySubject)
    throws Exception {
    Subject subj = createSubject(agentName);
    return doAs(subj, action, displaySubject);
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
        Object p = it.next();
        if(!(p instanceof ExecutionPrincipal)) {
	  _log.debug(p.toString());
        }
      }
    }
  }

  /** Add a principal to an existing chain of principals.
   */
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
	if (_log.isDebugEnabled()) {
	  _log.debug("principal:" + p.getClass().getName()
		     + " - " + p.toString());
	}
        // NOTE: This won't be the case going forward because this class is relocated
        //       to securityservice.jar
	// Do not use (p instanceof ChainedPrincipal) as 
	// the class may have been loaded by a different class loader.
        /*
	if (p.getClass().getName().
	    equals("org.cougaar.core.security.securebootstrap.ChainedPrincipal")) {
	*/

	if(p instanceof ChainedPrincipal) {
	  if (_log.isDebugEnabled()) {
	    _log.debug("Adding principals:" + p.toString());
	  }
          ChainedPrincipal oldCP = (ChainedPrincipal)p;
          cp.addChainedPrincipals(oldCP.getChain());

        // NOTE: This won't be the case going forward because this class is relocated
        //       to securityservice.jar
	  /* In the JDK 1.4 (at least on Linux, not tested on other platforms),
	   * the thread either hangs or dies when the following statement is executed:
	   *   ChainedPrincipal newP = (ChainedPrincipal)p;
	   * It must have something to do with the fact that p may be loaded
	   * by a different class loader than newP.
	   * Using introspection works.
	   */
	/*
	  try {
	    Class c = p.getClass();
	    Method m = c.getDeclaredMethod("getChain", null);
	    ArrayList newp = (ArrayList) m.invoke(p, null);
	    cp.addChainedPrincipals(newp);
	  }
	  catch (Exception e) {
	    System.out.println("Unable to get principal: " + e);
	  }
	*/
	  break;
	}
      }
    }
    else {
      if (_log.isDebugEnabled()) {
	_log.debug("No parent principal");
      }
    }
    if (_log.isDebugEnabled()) {
      _log.debug("Adding new principal:" + newPrincipal.toString());
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
    
    // add the execution principal if the execution context exists
    if(_context != null) {
      s.getPrincipals().add(new ExecutionPrincipal(_context));
    }
    
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

  private Subject createSubject(ExecutionContext ec) {
    final Subject s = new Subject();

    /* Adding the cluster identifier string as a principal
     * We could also add certificate credentials at this point.
     */
    Principal executionPrincipal = new ExecutionPrincipal(ec);
    s.getPrincipals().add(executionPrincipal);
 
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
  
  private void printPrincipalsInSubject(Subject subj) {
    if (_log.isDebugEnabled()) {
      CharArrayWriter caw = new CharArrayWriter();
      PrintWriter pw = new PrintWriter(caw);
      pw.print("Principals: ");
      Iterator it = subj.getPrincipals().iterator(); 
      while (it.hasNext()) {
	pw.print(it.next() + ". ");
      }
      Throwable t = new Throwable();
      t.printStackTrace(pw);
      pw.print("\nJaasClient. Calling doAs ");
      _log.debug(caw.toString());
    }
  }

  private Object doAs(Subject subj, java.security.PrivilegedAction action, boolean displaySubject) {
    Object o = null;

    if (_log.isDebugEnabled() && displaySubject) {
      printPrincipalsInSubject(subj);
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
    o = Subject.doAs(subj, action);

    if (_log.isDebugEnabled() && displaySubject) {
      _log.debug("JaasClient. doAs done ");
    }
    return o;
  }

  private Object doAs(Subject subj,
		      java.security.PrivilegedExceptionAction action,
		      boolean displaySubject)
    throws Exception {
    Object o = null;

    if (_log.isDebugEnabled() && displaySubject) {
      printPrincipalsInSubject(subj);
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
    o = Subject.doAs(subj, action);

    if (_log.isDebugEnabled() && displaySubject) {
      _log.debug("JaasClient. doAs done ");
    }
    return o;
  }

}
