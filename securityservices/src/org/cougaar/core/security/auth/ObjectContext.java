/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
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

package org.cougaar.core.security.auth;

import org.cougaar.core.mts.MessageAddress;

/**
 * The <code>ObjectContext</code> is the base interface that all
 * authorization models must use for the object-level security context.
 * The implemented object security context should contain all the 
 * member variables and accessors needed to verify permissions for
 * whether a blackboard object should be accessed when compared to
 * the execution security context derived from <code>ExecutionContext</code>.
 *
 * @see org.cougaar.core.security.auth.ExecutionContext
 * @author <a href="mailto:gmount@nai.com">George Mount</a>
 */
public interface ObjectContext {
  /**
   * Returns the agent identifier that caused this object to be
   * placed on the blackboard.
   *
   * @return The identifier for the agent that placed the
   *         object on the blackboard. <code>null</code> is returned
   *         when published by a local Agent's component.
   */
  public MessageAddress getSource();

  /**
   * Allows the source of the blackboard object. This method
   * is only allowed to be called by the LP's or blackboard itself.
   *
   * @param address The identifier for the agent which is causing the
   * object to be published to the blackboard.
   */
  public void setSource(MessageAddress address);
}
