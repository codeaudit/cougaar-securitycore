/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package org.cougaar.core.security.securebootstrap;

import java.security.Principal;

public final class StringPrincipal implements Principal
{
  private final String name;
  
  public StringPrincipal(String name) {
    if (name == null) {
      throw new IllegalArgumentException("Name cannot be null");
    }
    this.name = name;
  }
  public int hashCode() {
    return name.hashCode();
  }    
  public java.lang.String getName() {
    return name;
  }
  public java.lang.String toString() {
    return "StringPrincipal: " + name;
  }
  public boolean equals(java.lang.Object obj) {
    if (obj == null) return false;
    if (!(obj instanceof StringPrincipal))
      return false;
    StringPrincipal other =
      (StringPrincipal) obj;
    return name.equals(other.getName());
  }
}
