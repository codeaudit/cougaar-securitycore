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
 
 
 
 
 
 


package org.cougaar.core.security.auth;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Iterator;

public final class ChainedPrincipal
  implements Principal
{
  private ArrayList chain;
  
  public ChainedPrincipal() {
    chain = new ArrayList(0);
  }

  public ChainedPrincipal(ChainedPrincipal p) {
    chain = new ArrayList(0);
  }

  public int hashCode() {
    return chain.hashCode();
  }    

  public String getName() {
    String s = "";
    Iterator it = chain.iterator();
    for (int i = 1 ; it.hasNext() ; i++) {
      Principal p = (Principal) it.next();
      s = s + i + ":[" + p.getName() + "] ";
    }
    return s;

  }

  public String toString() {
    String s = "";
    for (int i = (chain.size() - 1) ; i >= 0 ; i--) {
      Principal p = (Principal) chain.get(i);
      s = s + (i + 1) + ":[" + p.toString() + "]\n";
    }
    return s;
  }

  public boolean equals(java.lang.Object obj) {
    if (obj == null) {
      return false;
    }
    if (!(obj instanceof ChainedPrincipal)) {
      return false;
    }
    ChainedPrincipal other = (ChainedPrincipal) obj;
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
