/*
 * <copyright>
 *  Copyright 1997-2003 Networks Associates Technology, Inc.
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
 */
package org.cougaar.core.security.auth;

import java.security.Principal;

public final class ExecutionPrincipal implements Principal {
  private ExecutionContext _context;
  
  public ExecutionPrincipal(ExecutionContext context) {
    _context = context;
  }
  
  public boolean equals(Object o) {
    if(this == o) {
      return true;
    }
    if(o instanceof ExecutionPrincipal) {
      ExecutionPrincipal ep = (ExecutionPrincipal)o;
      if(_context.equals(ep._context)) {
        return true;
      }
    }
    return false;
  }
  
  public String getName() {
    if (_context  != null) {
      return _context.toString();
    } else {
      return "";
    }
  }
  
  public int hashCode() {
    return _context.hashCode(); 
  }
  
  public String toString() {
    return "ExecutionPrincipal[\n" + _context.toString() + "]"; 
  }
  
  public ExecutionContext getExecutionContext() {
    return _context; 
  }
}
