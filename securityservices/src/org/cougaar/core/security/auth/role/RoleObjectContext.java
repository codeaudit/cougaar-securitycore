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
 


package org.cougaar.core.security.auth.role;

import java.io.Serializable;
import java.security.Permission;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.auth.ContextPermission;
import org.cougaar.core.security.auth.ObjectContext;

public class RoleObjectContext implements ObjectContext, Serializable {
  private MessageAddress _agent;
  private static final Permission SET_SOURCE_PERMISSION =
    new ContextPermission("setSource");

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
