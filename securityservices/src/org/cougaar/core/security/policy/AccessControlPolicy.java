/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.Entity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

/**
 * Access control policy class instance and policy contstants. The constants
 * are specific to access control policy. An instance should have a specific 
 * target agent (or possibly community).
 */
public class AccessControlPolicy
  extends SecurityPolicy {

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
  private HashMap commList = new HashMap();

  public static final String ACCEPT = "ACCEPT";
  public static final String SET_ASIDE = "SET_ASIDE";
  private HashMap agtActions = new HashMap();
  private HashMap agtActionsCom = new HashMap();
  public Object getAgentAction(String key){
    Object o = agtActions.get(key);
    //try community policy if null
    if(o==null && agtActionsCom.size()>0){
      //find which community the agent belongs to and get the policy
      String c = commLookup(key);
      if(c!=null){
        o = agtActionsCom.get(c);
      }
    }
    if(o==null) o=agtActions.get("DEFAULT");
    return o;
  }
  public void setAgentAction(String key, Object value){
    agtActions.put(key, value);
    return;
  }
  public void setComAgentAction(String key, Object value){
    agtActionsCom.put(key, value);
    commList.put(key,null); //put in null for now, fill in setCommunityService.
    return;
  }

  //lookup community name
  private String commLookup(String agent){
    Iterator iter = commList.keySet().iterator();
    while(iter.hasNext()){
      String comName = (String)iter.next();
      Collection v = (Collection)commList.get(comName);
      if (v != null){
        if(v.contains(agent)){
          return comName;
        }
      }
    }
    //fall through
    return null;
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
  private HashMap integrityCom = new HashMap();
  public Object getIntegrity(String key){
    Object o = integrity.get(key);
    //try community policy if null
    if(o==null && integrityCom.size()>0){
      //find which community the agent belongs to and get the policy
      String c = commLookup(key);
      if(c!=null){
        o = integrityCom.get(c);
      }
    }
    if(o==null) o=integrity.get("DEFAULT");
    return o;
  }
  public void setIntegrity(String key, Object value){
    integrity.put(key, value);
    return;
  }
  public void setComIntegrity(String key, Object value){
    integrityCom.put(key, value);
    commList.put(key,null); //put in null for now, fill in setCommunityService.
    return;
  }

  private HashMap verbs = new HashMap();
  private HashMap verbsCom = new HashMap();
  public Object getVerbs(String key){
    Object o = verbs.get(key);
    //try community policy if null
    if(o==null && verbsCom.size()>0){
      //find which community the agent belongs to and get the policy
      String c = commLookup(key);
      if(c!=null){
        o = verbsCom.get(c);
      }
    }
    if(o==null) o=verbs.get("DEFAULT");
    return o;
  }
  public void setVerbs(String key, Object value){
    verbs.put(key, value);
    return;
  }
  public void setComVerbs(String key, Object value){
    verbsCom.put(key, value);
    commList.put(key,null); //put in null for now, fill in setCommunityService.
    return;
  }

  private HashMap criticality = new HashMap();
  private HashMap criticalityCom = new HashMap();
  public Object getCriticality(String key){
    Object o = criticality.get(key);
    //try community policy if null
    if(o==null && criticalityCom.size()>0){
      //find which community the agent belongs to and get the policy
      String c = commLookup(key);
      if(c!=null){
        o = criticalityCom.get(c);
      }
    }
    if(o==null) o=criticality.get("DEFAULT");
    return o;
  }
  public void setCriticality(String key, Object value){
    criticality.put(key, value);
    return;
  }
  public void setComCriticality(String key, Object value){
    criticalityCom.put(key, value);
    commList.put(key,null); //put in null for now, fill in setCommunityService.
    return;
  }

  public void setCommunityService(CommunityService cs){
    //fill community info
    Iterator iter = commList.keySet().iterator();
    while(iter.hasNext()){
      final String comName = (String)iter.next();

      // TODO: This is very inefficient
      CommunityResponseListener crl = new CommunityResponseListener() {
	  public void getResponse(CommunityResponse resp) {
	    Object response = resp.getContent();
	    if (!(response instanceof Community)) {
	      String errorString = "Unexpected community response class:"
		+ response.getClass().getName() + " - Should be a Community";
	      throw new RuntimeException(errorString);
	    }
	    Collection entities = ((Community)response).getEntities();
	    Collection entityNames = new ArrayList(entities.size());
	    Iterator it = entities.iterator();
	    while (it.hasNext()) {
	      entityNames.add(((Entity) it.next()).getName());
	    }
	    commList.put(comName, entityNames);
	  }
	};
      cs.getCommunity(comName, crl);

    }
  }
  
  public String toString() {
  return "NAME:" + Name +
        " TYPE:" + Type +
        " DIRECTION:" + Direction 
  ;
  }

}
