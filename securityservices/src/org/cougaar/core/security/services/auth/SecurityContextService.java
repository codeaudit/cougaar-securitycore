/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 *
 */
package org.cougaar.core.security.services.auth;

// core imports
import org.cougaar.core.component.Service;

// security services imports
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
