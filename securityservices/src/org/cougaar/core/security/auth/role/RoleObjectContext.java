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

package org.cougaar.core.security.auth.role;

import org.cougaar.core.security.auth.ObjectContext;
import org.cougaar.core.security.auth.ContextPermission;
import org.cougaar.core.mts.MessageAddress;

import java.security.Permission;
import java.util.Arrays;
import java.util.List;

public class RoleObjectContext implements ObjectContext {
  private MessageAddress _agent;
  private static final Permission SET_SOURCE_PERMISSION =
    new ContextPermission("object", "setSource");

  RoleObjectContext(MessageAddress agent) {
    _agent = agent;
  }

  public MessageAddress getSource() {
    return _agent;
  }

  public void setSource(MessageAddress address) {
    SecurityManager sm = System.getSecurityManager();
    if (sm != null) {
      sm.checkPermission(SET_SOURCE_PERMISSION);
    }
    _agent = address;
  }

  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o instanceof RoleObjectContext) {
      RoleObjectContext roc = (RoleObjectContext) o;
      if (_agent == null) {
        return (roc._agent == null);
      }
      return _agent.equals(roc._agent);
    }
    return false;
  }

  public int hashCode() {
    return _agent.hashCode();
  }

  public String toString() {
    return "RoleObjectContext[" + _agent + ']';
  }
}
