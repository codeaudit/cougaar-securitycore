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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.HashSet;

public class BlackboardFilterPolicy extends SecurityPolicy {
  public static final String READ_ACCESS   = "read";
  public static final String WRITE_ACCESS  = "write";
  public static final String DENIED_ACCESS = "denied";
  public static class ReadOnlyRule implements java.io.Serializable {
    public String agent         = null;
    public String defaultAccess = null;
    public HashSet patterns      = null;
    public HashSet writeRoles    = null;
    public HashSet readRoles     = null;
    public HashSet deniedRoles   = null;

    private static void addTo(StringBuffer buf, HashSet list) {
      if (list != null) {
        Iterator iter = list.iterator();
        boolean first = true;
        while (iter.hasNext()) {
          if (first) first = false;
          else buf.append(',');
          buf.append(iter.next().toString());
        }
      }
    }

    public String toString() {
      StringBuffer buf = new StringBuffer();
      buf.append("ReadOnlyRule (")
        .append(agent).append(',')
        .append(defaultAccess).append(",[");
      addTo(buf,patterns);
      buf.append("],[");
      addTo(buf,writeRoles);
      buf.append("],[");
      addTo(buf,readRoles);
      buf.append("],[");
      addTo(buf,deniedRoles);
      buf.append("])");
      return buf.toString();
    }
  }

  private ArrayList _rules = new ArrayList();

  public ReadOnlyRule[] getRules() {
    return (ReadOnlyRule[]) _rules.toArray(new ReadOnlyRule[_rules.size()]);
  }

  public void addRule(ReadOnlyRule rule) {
    _rules.add(rule);
  }

  public String toString() {
    Iterator iter = _rules.iterator();
    StringBuffer buf = new StringBuffer("BlackboardFilterPolicy: (");
    while (iter.hasNext()) {
      buf.append(iter.next().toString());
    }
    return buf.toString();
  }
}
