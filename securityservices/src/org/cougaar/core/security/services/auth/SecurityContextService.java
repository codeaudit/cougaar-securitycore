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

package org.cougaar.core.security.services.auth;

// core imports
import org.cougaar.core.component.Service;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.ObjectContext;

/**
 * The SecurityContextService is used to set, get, or reset the execution or 
 * object context.
 *
 * Every setExecutionContext() call must be accompanied by a matching
 * resetExecutionContext() call.  For example,
 * <pre>
 *      setExecutionContext(scs.getSecurityContext());
 *      // execute code
 *      resetExecutionContext();
 * </pre>
 *
 * Inorder to use this service, a SecurityServicePermission must be given to the
 * code base that is using it.  To grant permission, add the following line to
 * the Java security policy:
 * <pre> 
 *      grant codeBase "file:${codebase}${/}jarfile.jar" signedBy "privileged" {
          ...
          permission org.cougaar.core.security.provider.SecurityServicePermission 
               "org.cougaar.core.security.services.auth.SecurityContextService";
          ...
 *      };
 * </pre>
 *
 */
public interface SecurityContextService extends Service {
   /**
    * Set the execution context for the current thread.
    *
    * @param ec the execution context to associate with the current thread
    */
   public void setExecutionContext(ExecutionContext ec);

   /**
    * Set the object context for a given object.
    *
    * @param oc the object context to associate with o
    * @param o object to associate the security context
    */
//    public void setObjectContext(ObjectContext oc, Object o);

   /**
    * Get the execution context for the current thread.
    *
    * @return the execution context for the current thread
    */
   public ExecutionContext getExecutionContext();

   /**
    * Get the execution context for the a given object.
    *
    * @param o an object
    * @return the execution context for object o
    */
   public ObjectContext getObjectContext(Object o);

   /**
    * Reset the execution context for the current thread to the previous execution context.
    *
    * @return the execution context for the current thread
    */
  public ExecutionContext resetExecutionContext();

   /**
    * Reset the execution context for a given object to the previous execution context.
    * 
    * @param o an object
    * @return the execution context for object o
    */
//    public ObjectContext resetObjectContext(Object o);

}
