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

package org.cougaar.core.security.auth;

import java.io.CharArrayWriter;
import java.io.PrintWriter;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Iterator;

import javax.security.auth.Subject;

import org.cougaar.core.security.acl.auth.URIPrincipal;
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
  
  public Object doAs(URIPrincipal up, java.security.PrivilegedAction action) {
    Subject subj = createSubject(up);
    return doAs(subj, action, false);  
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
        if(!(p instanceof ExecutionPrincipal) && _log.isDebugEnabled()) {
          _log.debug(p.toString());
        }
      }
    }
  }
  
  /**
   * Retrieves the ExecutionContext in which the current thread executes.
   * @return the ExecutionContext in which the current thread executes.
   */
  private static ExecutionContext getExecutionContext() {
    ExecutionContext ec = null;
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
        if (p instanceof ExecutionPrincipal) {
          ec = ((ExecutionPrincipal)p).getExecutionContext();
          break;
        }
      }
    }
    return ec;
  }
  
  /**
   * Retrieves the name of the agent in which the current thread executes.
   * It retrieves the name in a trusted manner.
   * @return the name of the agent in which the current thread executes.
   */
  public static String getAgentName() {
    String agentName = null;
    ExecutionContext ec = getExecutionContext();
    if (ec != null && ec.getAgent() != null) {
      agentName = ec.getAgent().toAddress();
    }
    return agentName;
  }
  
  /**
   * Retrieves the component name in which the current thread executes.
   * It retrieves the name in a trusted manner.
   * @return the name of the agent in which the current thread executes.
   */
  public static String getComponentName() {
    String componentName = null;
    ExecutionContext ec = getExecutionContext();
    if (ec != null) {
      componentName = ec.getComponent();
    }
    return componentName;
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
    AccessController.doPrivileged(new SetReadOnlyAction(s));
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
    AccessController.doPrivileged(new SetReadOnlyAction(s));
    return s;   
  }
  
  private Subject createSubject(URIPrincipal up) {
    Subject s = new Subject();
    s.getPrincipals().add(up);
    
    /* Modifications (additions and removals) to this Subject's Principal
     * Set and credential Sets will be disallowed. The destroy operation
     * on this Subject's credentials will still be permitted. 
     */
    AccessController.doPrivileged(new SetReadOnlyAction(s));
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
  
  class SetReadOnlyAction implements PrivilegedAction {
    Subject _s;
    SetReadOnlyAction(Subject s) {
      _s = s; 
    }
    public Object run() {
      _s.setReadOnly();
      return null; // nothing to return
    }
  } // end class SetReadOnlyAction
}
