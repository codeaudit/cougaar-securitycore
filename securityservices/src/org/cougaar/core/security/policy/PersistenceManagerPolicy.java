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


package org.cougaar.core.security.policy;

import java.io.Serializable;

public class PersistenceManagerPolicy
  extends SecurityPolicy implements Serializable
{
   //static final long serialVersionUID = -3939280448042844622L;
  private static final long serialVersionUID = -4786187937404204594L;

  // what type of communication to PM, currently only supports URL
  public String pmType;
  // URL to request key recovery
  public String pmUrl;
  // PM DN to retrieve certificate
  public String pmDN;
  
  public String toString() {
    return "(type=" + pmType +
           " url=" + pmUrl +
           " dn=" + pmDN + ")";
  }

  public int hashCode() {
    return pmType.hashCode() + pmUrl.hashCode() + pmDN.hashCode();
  }

  public boolean equals(Object obj) {
   if (obj == null || !(obj instanceof PersistenceManagerPolicy)) {
      return false;
    }
    PersistenceManagerPolicy pmp = (PersistenceManagerPolicy)obj;
    if (pmUrl != null && pmUrl.equals(pmp.pmUrl) &&
        pmDN != null && pmDN.equals(pmp.pmDN)) {
      return true;
    }
    else {
      return false;
    }
  }
}
