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

import java.util.HashMap;

/**
 * Access control policy class instance and policy contstants. The constants
 * are specific to access control policy. An instance should have a specific 
 * target agent (or possibly community).
 */
public class AccessControlPolicy extends SecurityPolicy {

  /**
   * to whom this policy is applied to.
   */
  public String NAME = "UNKNOWN";

  public static final int AGENT = 0;
  public static final int COMMUNITY = 1;
  public static final int SOCIETY = 2;
  public int TYPE = AGENT;

  public static final int INCOMING = 0;
  public static final int OUTGOING = 1;
  public static final int BOTH = 2;
  public int DIRECTION = BOTH;

  public static final int ACCEPT = 0;
  public static final int SET_ASIDE = 1;
  private HashMap actions = new HashMap();
  public Object getAction(String key){
    return actions.get(key);
  }
  public void setAction(String key, Object value){
    actions.put(key, value);
    return;
  }
  
  public static final int INTEGRITY0 = 0;
  public static final int INTEGRITY1 = 1;
  public static final int INTEGRITY2 = 2;
  public static final int INTEGRITY3 = 3;
  public static final int INTEGRITY4 = 4;
  public static final int INTEGRITY5 = 5;
  private HashMap trusts = new HashMap();
  public Object getTrust(String key){
    return trusts.get(key);
  }
  public void setTrust(String key, Object value){
    trusts.put(key, value);
    return;
  }

  private HashMap verbs = new HashMap();
  public Object getVerb(String key){
    return verbs.get(key);
  }
  public void setVerb(String key, Object value){
    verbs.put(key, value);
    return;
  }

  public String toString() {
  return "NAME:" + NAME +
        " TYPE:" + TYPE +
        " DIRECTION:" + DIRECTION 
  ;
  }

}
