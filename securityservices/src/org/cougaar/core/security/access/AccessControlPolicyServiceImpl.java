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

// Cougaar core services
import org.cougaar.core.service.LoggingService;
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
  private ServiceBroker serviceBroker;

  //named proxies
  HashSet proxies = new HashSet();

    //policy source
  Vector pp = new Vector();

  //directive verb look-up hashmap
  HashMap verbs = new HashMap();

  //agent actions look-up hashmap
  HashMap agentActions = new HashMap();

  //actions look-up HashMap
  HashMap actions = new HashMap();

  //Criticality attributes look-up HashMap
  HashMap crits = new HashMap();

  //integraty attributes look-up HashMap
  HashMap integs = new HashMap();

  //TrustSet map to transfer trust from parent to child child tasks
  private Hashtable trustTable = new Hashtable(20);


  protected boolean dbg = false;

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

    //setup for default policy
    AccessPolicyProxy app = new AccessPolicyProxy("DEFAULT", serviceBroker);
    if(app!=null){
      pp.add(app);
    }

    String db = secprop.getProperty(secprop.TRANSPORT_DEBUG,
				    "false");
    dbg = (db.equalsIgnoreCase("true") || (db.indexOf("security")>=0));
  }

  private void checkOrMakeProxy(String agent){
    if(proxies.contains(agent)) return;

    AccessPolicyProxy app = new AccessPolicyProxy(agent, serviceBroker);

    if(app!=null){
      pp.add(app);
      proxies.add(agent);
      if(dbg) {
	log.debug("Making proxy for agent " + agent);
      }
    }

    // If we need to add proxy, there is a good chance we need
    // a new certificate too so check for it.
    if(dbg) log.debug("checking certs for agent " + agent);
    keyRing.checkOrMakeCert(agent);

    return;
  }

  public synchronized TrustSet getIncomingTrust(String source, String target)
  {
    checkOrMakeProxy(target);
    HashMap h = (HashMap)crits.get(target);
    if(h==null) {
      h = (HashMap)crits.get("DEFAULT");
    }
    if(h==null) {
      return null;
    }

    Object obj = h.get(source + ":");
    if(obj==null) {
      obj = h.get("DEFAULT:");
    }
    if(obj==null) {
      return null;
    }
    if(dbg) {
      log.debug("Msg IN:" + source + "->" + target
			 + ". Criticality:" + obj);
    }

    TrustSet ts = new TrustSet();
    ts.addAttribute(new TrustAttribute(MissionCriticality.name, obj));

    h = (HashMap)integs.get(target);
    if(h==null) h = (HashMap)integs.get("DEFAULT");
    if(h==null) return ts;
    obj = h.get(source + ":");
    if(obj==null) obj = h.get("DEFAULT:");
    if(obj==null) return ts;

    if(dbg) {
      log.debug("Msg IN:" + source + "->" + target
			 +". Integrity:"+obj);
    }
    ts.addAttribute(new TrustAttribute(IntegrityAttribute.name, obj));

    return ts;
  }

  public synchronized TrustSet getOutgoingTrust(String source, String target) {
    checkOrMakeProxy(source);
    HashMap h = (HashMap)crits.get(source);
    if(h==null) h = (HashMap)crits.get("DEFAULT");
    if(h==null) return null;

    Object obj = h.get(":"+target);
    if(obj==null) obj = h.get(":DEFAULT");
    if(obj==null) return null;
    if(dbg) {
      log.debug("Msg OUT:" + source + "->" + target
			 + ". Criticality:"+obj);
    }

    TrustSet ts = new TrustSet();
    ts.addAttribute(new TrustAttribute(MissionCriticality.name, obj));

    h = (HashMap)integs.get(source);
    if(h==null) h = (HashMap)integs.get("DEFAULT");
    if(h==null) return ts;
    obj = h.get(":" + target);
    if(obj==null) obj = h.get(":DEFAULT");
    if(obj==null) return ts;
    if(dbg) {
      log.debug("Msg OUT:" + source + "->" + target
			 + ". Integrity:" + obj);
    }
    ts.addAttribute(new TrustAttribute(IntegrityAttribute.name, obj));

    return ts;
  }

  public synchronized String getIncomingAction(String target, String level){
    checkOrMakeProxy(target);
    HashMap h = (HashMap)actions.get(target);
    if(h==null) h = (HashMap)actions.get("DEFAULT");
    if(h==null) return null;
    String r = (String)h.get("Criticality"+level+":");
    if(dbg) {
      log.debug("Msg IN: ->" + target 
			 +". Action:" + r + " for level " + level);
    }
    return r;
  }

  public synchronized String getOutgoingAction(String source, String level){
    checkOrMakeProxy(source);
    HashMap h = (HashMap)actions.get(source);
    if(h==null) h = (HashMap)actions.get("DEFAULT");
    if(h==null) return null;
    String r = (String)h.get(":"+"Criticality"+level);
    if(dbg) {
      String s = "Msg OUT:" + source + "-> . Action:" +
	(r == null ? "No policy" : r) + " for level " + level;
      log.debug(s);
    }
    return r;
  }

  public synchronized String getIncomingAgentAction(String source,
						    String target) {
    checkOrMakeProxy(target);
    HashMap h = (HashMap)agentActions.get(target);
    if(h == null)h = (HashMap)agentActions.get("DEFAULT");
    if(h == null) {
      if(dbg) {
	log.debug("Msg IN: " + source + "->" + target
			   + "No AgentAction");
      }
      return null;
    }
    String r = (String)h.get("In:" + source);
    if(r == null) {
      r = (String)h.get("In:DEFAULT");
    }
    if(dbg) {
      log.debug("Msg IN:" + source + "->" + target +
			 ". Agent action:" + r);
    }
    return r;

  }

  public synchronized String getOutgoingAgentAction(String source,
						    String target) {
    checkOrMakeProxy(source);
    HashMap h = (HashMap)agentActions.get(source);
    if(h == null)h = (HashMap)agentActions.get("DEFAULT");
    if(h == null) {
      if(dbg)log.debug("Msg OUT: " + source + "->" + target
				+ "No AgentAction");
      return null;
    }
    String r = (String)h.get("Out:" + target);
    if(r == null) {
      r = (String)h.get("Out:DEFAULT");
    }
    if(dbg) {
      log.debug("Msg OUT: " + source + "->" + target
			 +". Outgoing agent action:" + r);
    }
    return r;
  }


  public synchronized Object[] getIncomingVerbs(String source, String target)
  {
    checkOrMakeProxy(target);
    try{
      HashMap h = (HashMap)verbs.get(target);
      if(h == null) {
	h = (HashMap)verbs.get("DEFAULT");
      }
      if(h == null) {
	if(dbg)log.debug("Msg IN: " + source + "->" + target
				  + ". No verb");
	return null;
      }
      Vector r = (Vector)h.get("In:" + source);
      if(r == null) {
	r = (Vector)h.get("In:DEFAULT");
      }
      if(dbg) {
	System.out.print("Msg IN:" + source + "->" + target
			 + ". Verbs:");
	for(int i = 0; i < r.size(); i++)
	  System.out.print(r.get(i).toString() + " ");
	log.debug("");
      }
      return r.toArray();
    }
    catch(Exception ex) {
      if(dbg){
	log.debug("Warning: bad verb list!");
	ex.printStackTrace();
      }
    }
    return new Verb[0];
  }

  public synchronized Object[] getOutgoingVerbs(String source, String target) {
    checkOrMakeProxy(source);
    HashMap h = (HashMap)verbs.get(source);
    if(h == null)h = (HashMap)verbs.get("DEFAULT");
    if(h == null) {
      if(dbg)log.debug("Msg OUT: " + source + "->" + target
				+ ". No verb");
      return null;
    }

    if(dbg) {
      Iterator keys = h.keySet().iterator();
      System.out.print("Msg OUT: " + source + "->" + target + ". Verbs:");
      while(keys.hasNext())
	System.out.print(" " + keys.next().toString());
      log.debug("");
    }
    Vector r = (Vector)h.get("Out:" + target);
    if(r == null) {
      r = (Vector)h.get("Out:DEFAULT");
    }
    if(dbg) {
      System.out.print("Msg OUT:" + source + "->" + target
		       +". Verbs:");
      for(int i = 0; i < r.size(); i++)
	System.out.print(r.get(i).toString() + ":"
			 + r.get(i).getClass().getName() + " ");
      log.debug("");
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

  public synchronized TrustSet getDirectiveTrust(String uid) {
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
      super("org.cougaar.core.security.policy.AccessControlPolicy",
	    "AccessControlPolicyService",
	    sb);
      agent = name;
      if(debug) log.debug("--adding AccessPolicyProxy for:"+ agent);
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
      if(debug) log.debug("--updating AccessPolicyProxy for:"
				   + agent);

      if(policy == null) {
	if (debug) {
	  log.debug("AccessPolicyProxy: no policy");
	}
	return;
      }
      //whom is the policy for?
      /*
      if((!policySubjectName.equals(agent)) && (!agent.equals("DEFAULT"))) {
	if (debug) {
	  log.debug("policy not for:"+agent
			     + " - Should be for " + policySubjectName);
	}
	return;
      }
      */

      //for each RuleParameter
      RuleParameter[] ruleParameters = policy.getRuleParameters();
      for (int j=0; j < ruleParameters.length; j++)
        {
	  //for now only process KeyRuleParameter
	  if(!(ruleParameters[j] instanceof KeyRuleParameter)) return;
	  KeyRuleParameter krp = (KeyRuleParameter)ruleParameters[j];
	  //process rules
	  String name = krp.getName();
	  String value = (String)krp.getValue();
	  KeyRuleParameterEntry[] entry = krp.getKeys();

	  if(name.endsWith("Verb")){
	    if(name.startsWith("Outgoing")) {
	      if(value!=null && value !="" ) {
		if(debug)
		  log.debug("--default out verbs specified for:"
				     + agent);
		updateVerb("Out:DEFAULT",value);
	      }

	      for(int i = 0; i < entry.length; i++) {
		updateVerb("Out:" + entry[i].getKey(),
			   entry[i].getValue());
	      }
	    }
	    if(name.startsWith("Incoming")) {
	      if(value!=null && value !="" ) {
		if(debug) {
		  log.debug("--default agentAction specified for:"
				     + agent);
		}
		updateVerb("In:DEFAULT", value);
	      }
	      for(int i = 0; i < entry.length; i++) {
		updateVerb("In:" + entry[i].getKey(), entry[i].getValue());
	      }
	    }
	  }
	  if(name.endsWith("AgentAction")){
	    if(name.startsWith("Outgoing")) {
	      if(value!=null && value !="" ) {
		if(debug) {
		  log.debug("--default agentAction specified for:"
				     + agent);
		}
		updateAgentAction("Out:DEFAULT",value);
	      }

	      for(int i = 0; i < entry.length; i++) {
		updateAgentAction("Out:" + entry[i].getKey(),
				  entry[i].getValue());
	      }
	    }
	    if(name.startsWith("Incoming")) {
	      if(value!=null && value !="" ) {
		if(debug) {
		  log.debug("--default agentAction specified for:"
				     + agent);
		}
		updateAgentAction("In:DEFAULT", value);
	      }
	      for(int i = 0; i < entry.length; i++) {
		updateAgentAction("In:" + entry[i].getKey(),
				  entry[i].getValue());
	      }
	    }
	  }
	  if(name.endsWith("MessageAction")){
	    if(name.startsWith("Outgoing")) {
	      if(value!=null && value !="" )
		if(debug) {
		  log.debug("--default messageAction specified for:"
				     + agent);
		}
	      for(int i = 0; i < entry.length; i++) {
		updateAction(":"+entry[i].getKey(), entry[i].getValue());
	      }
	    }
	    if(name.startsWith("Incoming")) {
	      if(value!=null && value !="" )
		if(debug) {
		  log.debug("--default messageAction specified for:"
				     + agent);
		}
	      for(int i = 0; i < entry.length; i++) {
		updateAction(entry[i].getKey()+":", entry[i].getValue());
	      }
	    }
	  }
	  if(name.endsWith("MessageCriticality")){
	    if(name.startsWith("Outgoing")) {
	      if(value!=null && value !="" ) {
		updateCriticality(":"+"DEFAULT",value);
	      }
	      for(int i = 0; i < entry.length; i++) {
		updateCriticality(":"+entry[i].getKey(), entry[i].getValue());
	      }
	    }
	    if(name.startsWith("Incoming")) {
	      if(value!=null && value !="" ) {
		updateCriticality("DEFAULT"+":",value);
	      }
	      for(int i = 0; i < entry.length; i++) {
		updateCriticality(entry[i].getKey()+":", entry[i].getValue());
	      }
	    }
	  }
	  if(name.endsWith("MessageIntegrity")){
	    if(name.startsWith("Outgoing")) {
	      if(value!=null && value !="" ) {
		updateIntegrity(":"+"DEFAULT",value);
	      }
	      for(int i = 0; i < entry.length; i++) {
		updateIntegrity(":"+entry[i].getKey(), entry[i].getValue());
	      }
	    }
	    if(name.startsWith("Incoming")) {
	      if(value!=null && value !="" ) {
		updateIntegrity("DEFAULT"+":",value);
	      }
	      for(int i = 0; i < entry.length; i++) {
		updateIntegrity(entry[i].getKey()+":", entry[i].getValue());
	      }
	    }
	  }
        }
    }

    private void updateVerb(String target, Object verbList) {
      HashMap h = (HashMap)verbs.get(agent);
      if(h == null) {
	h = new HashMap();
	verbs.put(agent, h);
      }
      Vector verbs = new Vector();
      try {
	StringTokenizer st = new StringTokenizer((String)verbList, ":");
	while(st.hasMoreTokens()) {
	  verbs.addElement(new Verb(st.nextToken()));
	}
	if(debug) {
	  System.out.print("ACPS: Verbs for " + target + " =");
	  Enumeration e = verbs.elements();
	  while(e.hasMoreElements())
	    System.out.print(" " + e.nextElement());
	}
      }
      catch(Exception ex) {
	if(debug) {
	  log.debug("ACPS: Bad verbs for agent " + target);
	  ex.printStackTrace();
	  log.debug("ACPS: Bad verbs for agent " + target);
	}
      }
      h.put(target, verbs);
      if(debug)log.debug("updateAgentAction(" + target + ","
				  + verbList + ")");
    }

    private void updateAgentAction(String target, Object action) {
      HashMap h = (HashMap)agentActions.get(agent);
      if(h == null) {
	h = new HashMap();
	agentActions.put(agent, h);
      }
      h.put(target, action);
      if(debug)log.debug("updateAgentAction(" + target + ","
				  + action + ")");
    }

    private void updateAction(String key, Object value){
      HashMap h;
      Object o = actions.get(agent);
      if(o!=null){
	h = (HashMap)o;
	h.put(key,value);
      }else{
	h = new HashMap();
	h.put(key,value);
	actions.put(agent,h);
      }
      if(debug)log.debug("updateAction(" + key + "," + value + ")");
    }

    private void updateCriticality(String key, Object value){
      HashMap h;
      Object o = crits.get(agent);
      if(o!=null){
	h = (HashMap)o;
	h.put(key,value);
      }else{
	h = new HashMap();
	h.put(key,value);
	crits.put(agent, h);
      }
    }

    private void updateIntegrity(String key, Object value){
      HashMap h;
      Object o = integs.get(agent);
      if(o!=null){
	h = (HashMap)o;
	h.put(key,value);
      }else{
	h = new HashMap();
	h.put(key,value);
	integs.put(agent,h);
      }
    }

    public String getAgentName() {
      return agent;
    }

    public String getAgentId() {
      return agent;
    }
  }

}
