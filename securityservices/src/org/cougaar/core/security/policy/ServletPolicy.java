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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ServletPolicy extends SecurityPolicy {
  private List _rules = new ArrayList();
  private long _failureDelay = 1000;
  private long _sessionLife = 60000; // 1 minute

  public static class ServletPolicyRule implements java.io.Serializable {
    public String agentName;
    public List   urls;
    public String auth;
    public List   roles;
    public boolean requireSSL = false;
    
    public String toString() {
      StringBuffer buf = new StringBuffer();
      buf.append("Rule (").append(agentName).append(",{");
      Iterator iter = urls.iterator();
      boolean first = true;
      while (iter.hasNext()) {
        if (first) first = false;
        else buf.append(", ");
        buf.append(iter.next());
      }

      buf.append("},").append(auth).append(",[");
      iter = roles.iterator();
      first = true;
      while (iter.hasNext()) {
        if (first) first = false;
        else buf.append(", ");
        buf.append(iter.next());
      }
      buf.append("])");
      return buf.toString();
    }
  }

  public void addRule(String agent, List urls, String auth, List roles,
                      boolean requireSSL) {
    ServletPolicyRule spr = new ServletPolicyRule();
    spr.agentName = agent;
    spr.urls = urls;
    spr.auth = auth;
    spr.roles = roles;
    spr.requireSSL = requireSSL;
    _rules.add(spr);
  }

  public void addRootRule(List urls, String auth, List roles, boolean requireSSL) {
    addRule(null, urls, auth, roles, requireSSL);
  }

  public List getRules() {
    return _rules;
  }

  public long getFailureDelay() {
    return _failureDelay;
  }

  public void setFailureDelay(long delay) {
    _failureDelay = delay;
  }

  public long getSessionLife() {
    return _sessionLife;
  }

  public void setSessionLife(long life) {
    _sessionLife = life;
  }

  public String toString() {
    StringBuffer buf = new StringBuffer();
    buf.append("ServletPolicy (");
    Iterator rules = _rules.iterator();
    boolean first = true;
    while (rules.hasNext()) {
      if (first) first = false;
      else buf.append(", ");
      buf.append(rules.next());
    }
    buf.append(')');
    return buf.toString();
  }
}
