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
import java.util.Collection;
import java.util.Iterator;

//cougaar services
import org.cougaar.core.service.community.CommunityService;

/**
 * Access control policy class instance and policy contstants. The constants
 * are specific to access control policy. An instance should have a specific 
 * target agent (or possibly community).
 */
public class AccessControlPolicy extends SecurityPolicy {

  /**
   * to whom this policy is applied to.
   */
  public String Name = "UNKNOWN";

  public static final int AGENT = 1;
  public static final int COMMUNITY = 2;
  public static final int SOCIETY = 3;
  public int Type = AGENT;

  public static final int INCOMING = 1;
  public static final int OUTGOING = 2;
  public static final int BOTH = 3;
  public int Direction = BOTH;
  private CommunityService commService = null;

  public static final String ACCEPT = "ACCEPT";
  public static final String SET_ASIDE = "SET_ASIDE";
  private HashMap agtActions = new HashMap();
  public Object getAgentAction(String key){
    Object o = agtActions.get(key);
    //try community policy if null
/*    if(o==null && commService!=null){
      //find which community the agent belongs to and get the policy
      Collection c = commService.listParentCommunities(key);
      if(c!=null){
        Iterator it = c.iterator();
        String cname = null;
        while(it.hasNext()){
          cname = (String)it.next();
          if(cname != null) o = agtActions.get(cname);
          if(o!=null) break;
        }
      }
    }
*/    if(o==null) o=agtActions.get("DEFAULT");
    return o;
  }
  public void setAgentAction(String key, Object value){
    agtActions.put(key, value);
    return;
  }

  private HashMap msgActions = new HashMap();
  public Object getMsgAction(String key){
    return msgActions.get(key);
  }
  public void setMsgAction(String key, Object value){
    msgActions.put(key, value);
    return;
  }
  
  private HashMap integrity = new HashMap();
  public Object getIntegrity(String key){
    Object o = integrity.get(key);
    //try community policy if null
/*    if(o==null && commService!=null){
      //find which community the agent belongs to and get the policy
      Collection c = commService.listParentCommunities(key);
      if(c!=null){
        Iterator it = c.iterator();
        String cname = null;
        while(it.hasNext()){
          cname = (String)it.next();
          if(cname != null) o = integrity.get(cname);
          if(o!=null) break;
        }
      }
    }
*/    if(o==null) o=integrity.get("DEFAULT");
    return o;
  }
  public void setIntegrity(String key, Object value){
    integrity.put(key, value);
    return;
  }

  private HashMap verbs = new HashMap();
  public Object getVerbs(String key){
    Object o = verbs.get(key);
    //try community policy if null
/*    if(o==null && commService!=null){
      //find which community the agent belongs to and get the policy
      Collection c = commService.listParentCommunities(key);
      if(c!=null){
        Iterator it = c.iterator();
        String cname = null;
        while(it.hasNext()){
          cname = (String)it.next();
          if(cname != null) o = verbs.get(cname);
          if(o!=null) break;
        }
      }
    }
*/    if(o==null) o=verbs.get("DEFAULT");
    return o;
  }
  public void setVerbs(String key, Object value){
    verbs.put(key, value);
    return;
  }

  private HashMap criticality = new HashMap();
  public Object getCriticality(String key){
    Object o = criticality.get(key);
    //try community policy if null
/*    if(o==null && commService!=null){
      //find which community the agent belongs to and get the policy
      Collection c = commService.listParentCommunities(key);
      if(c!=null){
        Iterator it = c.iterator();
        String cname = null;
        while(it.hasNext()){
          cname = (String)it.next();
          if(cname != null) o = criticality.get(cname);
          if(o!=null) break;
        }
      }
    }
*/   if(o==null) o=criticality.get("DEFAULT");
    return o;
  }
  public void setCriticality(String key, Object value){
    criticality.put(key, value);
    return;
  }

  public void setCommunityService(CommunityService cs){
    commService = cs;
  }
  
  public String toString() {
  return "NAME:" + Name +
        " TYPE:" + Type +
        " DIRECTION:" + Direction 
  ;
  }

}
