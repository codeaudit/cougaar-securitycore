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
 */

package org.cougaar.core.security.auth;

import org.cougaar.core.mts.MessageAddress;

/**
 * The <code>ExecutionContext</code> is the security context base
 * interface that all authorization models must use to derive their
 * execution security context. The implemented class should define
 * any attributes that it requires to determine which
 * Permissions, based on the user, component, and agent that the
 * execution path may have access to.
 * <p>
 * The <code>ExecutionContext</code> is used in combination with
 * the <code>ObjectContext</code> to check Permissions.
 *
 * @see org.cougaar.core.security.authorization.ObjectContext
 */
public interface ExecutionContext {
  /**
   * Returns the agent identifier for this context. 
   *
   * @return The MessageAddress for the agent or <tt>null</tt> if no
   *         agent is specified for this context.
   */
  public MessageAddress getAgent();
}
