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
import java.util.ArrayList;
import java.util.Iterator;

public final class ChainedPrincipal implements Principal
{
  private ArrayList chain;
  
  public ChainedPrincipal() {
    chain = new ArrayList(0);
  }

  public int hashCode() {
    return chain.hashCode();
  }    

  public java.lang.String getName() {
    String s = "";
    Iterator it = chain.iterator();
    for (int i = 1 ; it.hasNext() ; i++) {
      Principal p = (Principal) it.next();
      s = s + i + ":[" + p.getName() + "] ";
    }
    return s;

  }

  public java.lang.String toString() {
    String s = "";
    Iterator it = chain.iterator();
    for (int i = 1 ; it.hasNext() ; i++) {
      Principal p = (Principal) it.next();
      s = s + i + ":[" + p.toString() + "]\n";
    }
    return "ChainedPrincipal: \n" + s;
  }

  public boolean equals(java.lang.Object obj) {
    if (obj == null) return false;
    if (!(obj instanceof ChainedPrincipal))
      return false;
    ChainedPrincipal other =
      (ChainedPrincipal) obj;
    return chain.equals(other.chain);
  }

  public void addChainedPrincipals(ArrayList c)
  {
    chain.addAll(c);
  }

  public void addPrincipal(Principal p)
  {
    chain.add(p);
  }

  public ArrayList getChain()
  {
    return chain;
  }
}
