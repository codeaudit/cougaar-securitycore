/**
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 *
 * Created on September 27, 2001, 3:43 PM
 */

package org.cougaar.core.security.access;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.HashSet;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.Iterator;
import java.util.Collection;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.planning.ldm.policy.*;
import org.cougaar.planning.ldm.plan.Verb;

// KAoS
import safe.enforcer.AgentEnforcer;

// Cougaar Security Services
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.crypto.KeyRing;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.services.acl.AccessControlPolicyService;
import org.cougaar.core.security.acl.trust.*;

public class AccessControlPolicyServiceImpl
  implements AccessControlPolicyService
{
  private KeyRingService keyRing = null;
  private SecurityPropertiesService secprop = null;
  private LoggingService log;
  private CommunityService commu;
  private ServiceBroker serviceBroker;

  //named proxies
  HashSet proxies = new HashSet();

  //policy source
  Vector pp = new Vector();

  //policy for society--usually the default, one-fits-all policy
  AccessControlPolicy acp_in = null;
  AccessControlPolicy acp_out = null;
  
  //policy for community--common policy for the team
  HashMap incoming_c = new HashMap();
  HashMap outgoing_c = new HashMap();

  //policy for agent--the one and only
  HashMap incoming_a = new HashMap();
  HashMap outgoing_a = new HashMap();

  //TrustSet map to transfer trust from parent to child child tasks
  private Hashtable trustTable = new Hashtable(20);

    /** Creates new AccessControlPolicyServiceImpl */
  public AccessControlPolicyServiceImpl(ServiceBroker sb) {
    serviceBroker = sb;
    // Get keyring service
    keyRing = (KeyRingService)
      serviceBroker.getService(this,
		    KeyRingService.class,
		    null);

    // Get Security Properties service
    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
		    SecurityPropertiesService.class,
		    null);

    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    
    commu = (CommunityService)
      serviceBroker.getService(this, CommunityService.class, null);

    //setup for default policy
    AccessPolicyProxy app = new AccessPolicyProxy("DEFAULT", serviceBroker);
    if(app!=null){
      pp.add(app);
    }
  }//Constructor

  private AccessControlPolicy getIncomingPolicy(String target){
    //try agent first
    AccessControlPolicy acp = (AccessControlPolicy)incoming_a.get(target);
    
    if(acp==null && commu!=null){
      //find which community the agent belongs to and get the policy
      Collection c = commu.listParentCommunities(target);
      if(c!=null){
        String cname = null;
        try{
          //agent could belongs to multiple communities, thus multiple set
          //of policy--no policy consolidation for now, just pick one.
          cname = (String)c.iterator().next();
        }catch(Exception e){
          log.debug("AccessControlPolicyServiceImpl: getting odd community name.");
        }
        if(cname != null && incoming_c !=null) 
          acp = (AccessControlPolicy)incoming_c.get(target);
      }
    }
    
    if(acp==null){
      //last try
      acp = acp_in;
    }
    
    if(acp==null){
      if(log.isDebugEnabled()) {
        log.debug("AccessControlPolicy ERROR: can't find policy for " 
        + "->" +  target);
      }
    }
      return acp;
  }//getIncomingPolicy

  private AccessControlPolicy getOutgoingPolicy(String source){
    //try agent first
    AccessControlPolicy acp = (AccessControlPolicy)outgoing_a.get(source);
    
    if(acp==null && commu!=null){
      //find which community the agent belongs to and get the policy
      Collection c = commu.listParentCommunities(source);
      if(c!=null){
        String cname = null;
        try{
          //agent could belongs to multiple communities, thus multiple set
          //of policy--no policy consolidation for now, just pick one.
          cname = (String)c.iterator().next();
        }catch(Exception e){
          log.debug("AccessControlPolicyServiceImpl: getting odd community name.");
        }
        if(cname != null && outgoing_c !=null) 
          acp = (AccessControlPolicy)outgoing_c.get(source);
      }
    }
    
    if(acp==null){
      //last try
      acp = acp_out;
    }
    
    if(acp==null){
      if(log.isDebugEnabled()) {
        log.debug("AccessControlPolicy ERROR: can't find policy for " 
        + source + "->" );
      }
    }
      return acp;
  }//getOutgoingPolicy
  
  private void checkOrMakeProxy(String agent){
    if(proxies.contains(agent)) return;

    AccessPolicyProxy app = new AccessPolicyProxy(agent, serviceBroker);

    if(app!=null){
      pp.add(app);
      proxies.add(agent);
      if(log.isDebugEnabled()) {
	log.debug("Making proxy for agent " + agent);
      }
    }

    // If we need to add proxy, there is a good chance we need
    // a new certificate too so check for it.
    if(log.isDebugEnabled()) log.debug("checking certs for agent " + agent);
    try{
      keyRing.checkOrMakeCert(agent);
    }catch(Exception e){
      log.debug("Error checking certs for agent" + agent);
    }

    return;
  }//checkOrMakeProxy

  public TrustSet getIncomingTrust(String source, String target)
  {
    checkOrMakeProxy(target);
    AccessControlPolicy acp = getIncomingPolicy(target);
    if(acp==null){
      //no point to go on.
      return null;
    }

    Object obj = acp.getCriticality(source);
    if (obj==null) return null;
    
    if(log.isDebugEnabled()) {
      log.debug("Msg IN:" + source + "->" + target
       + ". Criticality:" + obj);
    }
    TrustSet ts = new TrustSet();
    ts.addAttribute(new TrustAttribute(MissionCriticality.name, obj));

    obj = acp.getIntegrity(source);
    if (obj==null) return null;

    if(log.isDebugEnabled()) {
      log.debug("Msg IN:" + source + "->" + target
			 +". Integrity:"+obj);
    }
    ts.addAttribute(new TrustAttribute(IntegrityAttribute.name, obj));

    return ts;
  }//getIncomingTrust

  public TrustSet getOutgoingTrust(String source, String target) {
    checkOrMakeProxy(source);
    AccessControlPolicy acp = getOutgoingPolicy(source);
    if(acp==null){
      //no point to go on.
      return null;
    }
    
    Object obj = acp.getCriticality(target);
    if (obj==null) return null;
    
    if(log.isDebugEnabled()) {
      log.debug("Msg OUT:" + source + "->" + target
       + ". Criticality:" + obj);
    }

    TrustSet ts = new TrustSet();
    ts.addAttribute(new TrustAttribute(MissionCriticality.name, obj));

    obj = acp.getIntegrity(target);
    if (obj==null) return null;

    if(log.isDebugEnabled()) {
      log.debug("Msg OUT:" + source + "->" + target
			 +". Integrity:"+obj);
    }
    ts.addAttribute(new TrustAttribute(IntegrityAttribute.name, obj));

    return ts;
  }//getOutgoingTrust

  public String getIncomingAction(String target, String level){
    checkOrMakeProxy(target);
    AccessControlPolicy acp = getIncomingPolicy(target);
    if(acp==null){
      //no point to go on.
      return null;
    }

    String r = (String)acp.getMsgAction(level);
    if(log.isDebugEnabled()) {
      String s = "Msg In:" + "->" + target + ". Action:" +
    	(r == null ? "No policy" : r) + " for level " + level;
      log.debug(s);
    }
    return r;
  }//getIncomingAction

  public String getOutgoingAction(String source, String level){
    checkOrMakeProxy(source);
    AccessControlPolicy acp = getOutgoingPolicy(source);
    if(acp==null){
      //no point to go on.
      return null;
    }
    
    String r = (String)acp.getMsgAction(level);
    if(log.isDebugEnabled()) {
      String s = "Msg OUT:" + source + "->" + ". Action:" +
    	(r == null ? "No policy" : r) + " for level " + level;
      log.debug(s);
    }
    return r;
  }//getOutgoingAction

  public String getIncomingAgentAction(String source,
						    String target) {
    checkOrMakeProxy(target);
    AccessControlPolicy acp = getIncomingPolicy(target);
    if(acp==null){
      //no point to go on.
      return null;
    }

    String r = (String)acp.getAgentAction(source);
    if(log.isDebugEnabled()) {
      log.debug("Msg IN:" + source + "->" + target +
			 ". Agent action:" + r);
    }
    return r;
  }//getIncomingAgentAction

  public String getOutgoingAgentAction(String source,
						    String target) {
    checkOrMakeProxy(source);
    AccessControlPolicy acp = getOutgoingPolicy(source);
    if(acp==null){
      //no point to go on.
      return null;
    }
    
    String r = (String)acp.getAgentAction(target);
    if(log.isDebugEnabled()) {
      log.debug("Msg OUT: " + source + "->" + target
			 +". Outgoing agent action:" + r);
    }
    return r;
  }//getOutgoingAgentAction

  public Object[] getIncomingVerbs(String source, String target)
  {
    checkOrMakeProxy(target);
    AccessControlPolicy acp = getIncomingPolicy(target);
    if(acp==null){
      //no point to go on.
      return null;
    }
    
    Vector r = (Vector)acp.getVerbs(source);
    if(log.isDebugEnabled()) {
      log.debug("Msg IN:" + source + "->" + target
         + ". Verbs:");
      for(int i = 0; i < r.size(); i++)
        log.debug(r.get(i).toString() + " ");
    }
    Verb[] verbs = new Verb[0];
    try {
      return (Verb[])r.toArray(verbs);
    }
    catch(Exception ex) {
      log.debug("Warning: bad verb array:" + ex);
    }
    return verbs;
  }

  public Object[] getOutgoingVerbs(String source, String target) {
    checkOrMakeProxy(source);
    AccessControlPolicy acp = getOutgoingPolicy(source);
    if(acp==null){
      //no point to go on.
      return null;
    }

    Vector r = (Vector)acp.getVerbs(target);
    if(log.isDebugEnabled()) {
      log.debug("Msg OUT:" + source + "->" + target
		       +". Verbs:");
      for(int i = 0; i < r.size(); i++)
      log.debug(r.get(i).toString() + ":"
			 + r.get(i).getClass().getName() + " ");
    }
    Verb[] verbs = new Verb[0];
    try {
      return (Verb[])r.toArray(verbs);
    }
    catch(Exception ex) {
      log.debug("Warning: bad verb array:" + ex);
    }
    return verbs;
  }

  public TrustSet getDirectiveTrust(String uid) {
    return (TrustSet)trustTable.get((Object)uid);
  }

  public synchronized void setDirectiveTrust(String uid, TrustSet trust) {
    trustTable.put((Object)uid, (Object)trust);
  }

  /** ********************************************************************
   *  AccessPolicyProxy
   */
  private class AccessPolicyProxy
    extends GuardRegistration
    implements AgentEnforcer
  {
    private String agent;
    //private boolean debug=this.debug;
    public AccessPolicyProxy(String name, ServiceBroker sb) {
      super("org.cougaar.core.security.policy.AccessControlPolicy", name, sb);
      agent = name;
      if(log.isDebugEnabled())
	log.debug("--adding AccessPolicyProxy for:"+ agent);
      try {
      	registerEnforcer();
      }
      catch(Exception ex) {
        ex.printStackTrace();
      }
    }

    public void receivePolicyMessage(Policy policy,
				     String policyID,
				     String policyName,
				     String policyDescription,
				     String policyScope,
				     String policySubjectID,
				     String policySubjectName,
				     String policyTargetID,
				     String policyTargetName,
				     String policyType) {
      if(log.isDebugEnabled())
	log.debug("Got outdated policy format at AccessPolicyProxy for:"
		  + agent);
    }

    public void receivePolicyMessage(SecurityPolicy policy,
				     String policyID,
				     String policyName,
				     String policyDescription,
				     String policyScope,
				     String policySubjectID,
				     String policySubjectName,
				     String policyTargetID,
				     String policyTargetName,
				     String policyType) {
      if(log.isDebugEnabled())
	log.debug("--updating AccessPolicyProxy for:"
		  + agent);
      
      if(!(policy instanceof AccessControlPolicy)) {
        if (log.isDebugEnabled()) {
          log.debug("AccessPolicyProxy: wrong policy type.");
        }
        return;
      }
      
      AccessControlPolicy acp = (AccessControlPolicy)policy;
      
      switch(acp.Type){
      case  AccessControlPolicy.AGENT:
        if(acp.Direction == AccessControlPolicy.INCOMING){
          incoming_a.put(acp.Name,acp);
        }else if(acp.Direction == AccessControlPolicy.OUTGOING){
          outgoing_a.put(acp.Name,acp);
        }else if(acp.Direction == AccessControlPolicy.BOTH){
          incoming_a.put(acp.Name,acp);
          outgoing_a.put(acp.Name,acp);
        }
        break;
      case  AccessControlPolicy.COMMUNITY:
        if(acp.Direction == AccessControlPolicy.INCOMING){
          incoming_c.put(acp.Name,acp);
        }else if(acp.Direction == AccessControlPolicy.OUTGOING){
          outgoing_c.put(acp.Name,acp);
        }else if(acp.Direction == AccessControlPolicy.BOTH){
          incoming_c.put(acp.Name,acp);
          outgoing_c.put(acp.Name,acp);
        }
        break;
      case  AccessControlPolicy.SOCIETY:
        if(acp.Direction == AccessControlPolicy.INCOMING){
          acp_in = acp;
        }else if(acp.Direction == AccessControlPolicy.OUTGOING){
          acp_out = acp;
        }else if(acp.Direction == AccessControlPolicy.BOTH){
          acp_in = acp;
          acp_out = acp;
        }
      }
      return;
    }
    
    public String getAgentName() {
      return agent;
    }

    public String getAgentId() {
      return agent;
    }
  }

}
