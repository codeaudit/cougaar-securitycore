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


package org.cougaar.core.security.services.acl;

import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;

import org.cougaar.core.component.Service;

/** This service provides principal-based security contexts.
 *  It can be used by components that use the container model.
 *  A parent (container) can execute a child component under
 *  a principal-based security context.
 */
public interface JaasContainerService extends Service {

  /**
   *  Execute a component under a security context associated
   *  with a principal.
   *
   *  The doAs method should be called by any  that wishes to
   *  run another component in a specific access controller context
   *  with associated principals.
   *
   *  Executing a component under a principal-based context allows
   *  the following capabilities:
   *  
   *  1) A policy may be associated with a particular instance of
   *     a component, instead of the code-based policies.
   *  2) The security manager has access to the stack of principals
   *     when an access control check is performed.
   *  3) Instance information can be retrieved by the Security Manager
   *     when the contained component does not comply with the policy.
   *  4) A component cannot change the principals that was set by
   *     its container
   *  5) A container has to go through the security service to set
   *     security contexts.
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
   *
   * @param child   the principal under which the child should be
   * executed.
   * @param action  the method to execute under the child principal.
   * The child may only throw runtime exceptions.
   * @return an object that may be returned by the PrivilegedAction
   * of the child.
   */
  public Object doAs(Principal child, PrivilegedAction action);

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
   *
   * @param child   the principal under which the child should be
   * executed.
   * @param action  the method to execute under the child principal.
   * The child may throw checked and runtime exceptions.
   * @return an object that may be returned by the PrivilegedAction
   * of the child.
   */
  public Object doAs(Principal child, PrivilegedExceptionAction action)
    throws Exception;
}
