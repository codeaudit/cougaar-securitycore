/*
 * <copyright>
 *  Copyright 1997-2003 Network Associates
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
 */

package org.cougaar.core.security.services.auth;

// cougaar classes
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.component.ComponentDescription;
import org.cougaar.core.component.Service;
// security services classes
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.ObjectContext;
// java classes
import java.security.Permission;

/**
 *
 * @see org.cougaar.core.security.auth.ExecutionContext
 * @see org.cougaar.core.security.auth.ObjectContext
 *
 */
public interface AuthorizationService extends Service {
  public ExecutionContext createExecutionContext(MessageAddress agent,
                                                 ComponentDescription component);

  public ExecutionContext createExecutionContext(MessageAddress agent,
                                                 String uri, String userName);

  public ObjectContext createObjectContext(ExecutionContext ec, Object object);
  
  public void checkPermission(Permission perm);
  
  public void checkPermission(Permission perm, Object context);
                            
}
