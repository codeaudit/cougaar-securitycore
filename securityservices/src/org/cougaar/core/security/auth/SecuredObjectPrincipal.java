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

import java.security.Principal;
import java.lang.reflect.Method;

public class SecuredObjectPrincipal implements Principal {
  private final SecuredObject _obj;

  // NOTE: CougaarSecurityManager assumes there is only ONE constructor
  public SecuredObjectPrincipal(SecuredObject obj) {
    _obj = obj;
  }

  public boolean equals(Object another) {
    if (another instanceof SecuredObjectPrincipal) {
      SecuredObjectPrincipal p = (SecuredObjectPrincipal) another;
      return _obj.equals(p._obj);
    }
    return false;
  }

  public String getName() {
    return _obj.getClass().getName();
  }

  public int hashCode() {
    return _obj.hashCode();
  }

  public String toString() {
    return getName();
  }

  public ObjectContext getObjectContext() {
    return _obj.getObjectContext();
  }

  public SecuredObject getObject() {
    return _obj;
  }
}
