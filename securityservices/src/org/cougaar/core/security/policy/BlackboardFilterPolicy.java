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
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;

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

  public static class SelectRule implements java.io.Serializable {
    public String  agent         = null;
    public HashSet patterns      = null;
    public HashSet roles         = null;
    public HashSet methods       = null;

    public String toString() {
      StringBuffer buf = new StringBuffer();
      buf.append("ReadOnlyRule (")
        .append(agent).append(",[");
      addTo(buf,patterns);
      buf.append("],[");
      addTo(buf,methods);
      buf.append("],[");
      addTo(buf,roles);
      buf.append("])");
      return buf.toString();
    }
  }

  private ArrayList _readOnlyRules = new ArrayList();
  private ArrayList _selectRules   = new ArrayList();

  protected static void addTo(StringBuffer buf, Collection list) {
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

  public ReadOnlyRule[] getReadOnlyRules() {
    return (ReadOnlyRule[]) 
      _readOnlyRules.toArray(new ReadOnlyRule[_readOnlyRules.size()]);
  }

  public void addReadOnlyRule(ReadOnlyRule rule) {
    _readOnlyRules.add(rule);
  }

  public SelectRule[] getSelectRules() {
    return (SelectRule[]) 
      _selectRules.toArray(new SelectRule[_selectRules.size()]);
  }

  public void addSelectRule(SelectRule rule) {
    _selectRules.add(rule);
  }

  public String toString() {
    StringBuffer buf = new StringBuffer("BlackboardFilterPolicy: (");
    addTo(buf,_readOnlyRules);
    buf.append("),(");
    addTo(buf,_selectRules);
    buf.append(")");
    return buf.toString();
  }
}
