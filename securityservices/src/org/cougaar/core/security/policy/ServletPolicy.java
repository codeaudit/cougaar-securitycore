/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
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

package org.cougaar.core.security.policy;

import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

public class ServletPolicy extends SecurityPolicy {
  private List _rules = new ArrayList();
  private long _failureDelay = 1000;

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
