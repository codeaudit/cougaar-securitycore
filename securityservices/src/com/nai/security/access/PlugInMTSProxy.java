
/*
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
 * Created on October 22, 2001, 2:02 PM EDT
 */


package com.nai.security.access;

import java.util.*;

import com.nai.security.policy.*;
import org.cougaar.core.cluster.*;
import org.cougaar.core.mts.*;
import org.cougaar.core.plugin.*;
import org.cougaar.core.society.*;
import org.cougaar.domain.planning.ldm.policy.*;
import org.cougaar.util.*;
import org.cougaar.domain.planning.ldm.plan.*;

public class PlugInMTSProxy extends MessageTransportServiceProxy  
{
    /**
     * Determines whether a proxy should display debugging information
     */
    private static boolean debug = Boolean.getBoolean(
	System.getProperty("org.cougaar.core.security.access.Debug", "true"));

    /** 
     * The name of the agent or node on whose behalf this proxy mediates.
     */
    private String name = null;

    /**
     * A cache of access control policy rules to be used in determining
     * how to set trust attributes and message routing rules.
     */
    private MTSPolicyCache cache = null;


    /** a queue for messages that have been set aside */
    protected MessageLog setAsideLog = new MessageLog(10);
    /** a queue for messages that have been forwarded */
    protected MessageLog forwardLog = new MessageLog(10);
    /** a queue for messages that been accepted */
    protected MessageLog acceptLog = new MessageLog(30);
    /** a queue for message that have been allow to be transmitted */
    protected MessageLog outLog = new MessageLog(30);


    static protected Hashtable binders = new Hashtable(100);

    /**
     * A default constructor which creates a new policy cache to subscribe to
     * access control policies for this proxy's message transport client.
     *
     * @param client an agent or node, which represents an MTS client
     * @param service the message transport service 
     */
    public PlugInMTSProxy
	(MessageTransportService service, MessageTransportClient client)
    {
	super(service, client);
	 cache = new MTSPolicyCache(getUID());
	 if(debug)System.out.println("MTSProxy: new " + getUID());

    }

    public void receiveMessage(Message msg) 
    {   
	if (cache.isEmpty())    //policy not yet available
	    return;
	try {
	    incomingMessageIntegrity(msg);
	    incomingMessageCriticality(msg);
	    //incomingMessageAction(msg);
	}
	catch(Exception ex) {
	    if(debug) {
		System.out.println("MTSProxy: Exception caught! WARNING ONLY");
		ex.printStackTrace();
	    }
	}
    }

    public void sendMessage(Message msg)
    {   
	if(debug){
	    System.out.println("MTSProxy: pre-process message = " + 
			       messageToString(msg));
	}
	if (cache.isEmpty())     //policy not yet available
	    return;
	try {
	    outgoingMessageIntegrity(msg);
	    outgoingMessageCriticality(msg);
	    //outgoingMessageAction(msg);
            outLog.add(msg);
        }
	catch(Exception ex) {
	    if(debug) {
		System.out.println("MTSProxy: Exception caught! WARNING ONLY");
		ex.printStackTrace();
	    }
	}
    }


   // protected int lookup(String source, String trustType)
   // {
        //RuleParameter destRule = policy.lookup(source, destAgent, trustType);
        // look up specified trust attribute minimum level
        //return 4;
   // }

    protected void incomingMessageAction(Message msg) 
    {
	PolicyRuleBean policy = 
	    cache.get(AccessControlPolicy.IN_MSG_ACTION, 
		      msg.getOriginator().toString());
	if(policy == null)
	    return;
	
    }

    protected void incomingMessageAction(DirectiveMessage msg)
    {
	Directive[] directive = msg.getDirectives();
//	TrustSet[] trust = msg.getTrustSets();

	for(int i = 0; i < directive.length; i++) {
//	    try {
//		incomingMessageAction(directive[i], trust[i]);
//	    }
//	    catch(Exception ex) {
//		System.out.println(
//		 "PlugInMTSProxy: warning unable to process directive " 
//		 + i);
//		if(debug)ex.printStackTrace();
//	    }
	}
    }

    protected void incomingMessageAction(Directive dir, TrustSet set)
    {
	
    }

    

    protected void outgoingMessageAction(Message msg)
    {
	PolicyRuleBean policy = 
	    cache.get(AccessControlPolicy.IN_MSG_ACTION, 
		      msg.getTarget().toString());
	if(policy == null)
	    return;
	Object value = (String)policy.getValue();
	if(value instanceof String[]) {
	    String[] action = (String[])value;
	    if(action[0].equals(AccessControlPolicy.FORWARD)) {
		//send the message on its merry way
		msg.setTarget(new ClusterIdentifier(action[1]));
		server.sendMessage(msg);
		if(debug)System.out.println("MTSProxy: forwarding msg to " + 
					    action[1]);
	    }
        }
	if(value instanceof String) {
	    String action = (String)value;
	    if(action.equals(AccessControlPolicy.ACCEPT)) {
		//send the message on its merry way
		server.sendMessage(msg);
	    }
	    else if(action.equals(AccessControlPolicy.SET_ASIDE)) {
		//set aside the message--place in the set aside queue
		//setAsideLog.add(msg);
	    }
	}
    }

    /*
    private boolean messageAction(Message msg, String xmlParamName){
        System.out.println("In messageAction ");
        MissionCriticality criticality = 
	    msg.getTrustSet().getMissionCriticality();
        PolicyRuleBean ruleBean = null;
        if (criticality!=null) {
            String key = xmlParamName + ":Criticality" + criticality.getValue();
            System.out.println("key is: " + key);
            ruleBean = (PolicyRuleBean)rulesCache.get(key);
            //System.out.println("ruleBean is: " + ruleBean.toString());
            //look for a default
            if (ruleBean == null) {
                key = xmlParamName + ":DEFAULT";
                ruleBean = (PolicyRuleBean)rulesCache.get(key);
                System.out.println("new key is: " + key);
            }
        }
        else {  //if we have no matching routing rule then let the message pass
            System.out.println("no ruleBean found, create new ruleBean");
            ruleBean = new PolicyRuleBean();
            ruleBean.setValue(ACCEPT);
        }

        if (ruleBean == null) {
            System.out.println("ruleBean is null");
            return true;
        }
        System.out.println("ruleBean is: " + ruleBean.toString());

        if (actionIsForwardTo((Object)ruleBean.getValue())) {
            MessageAddress target = new MessageAddress(newMessageDestination);
                if (msg instanceof DirectiveMessage) {
                Directive[] directives = ((DirectiveMessage)msg).getDirectives();
                for (int i=0; i<directives.length; i++) {
                    if (((DirectiveMessage)msg).getDirectives()[0] instanceof Task) {
                        Task task = (Task)((DirectiveMessage)msg).getDirectives()[0];
                        if (task.getVerb().equals(new Verb("Transport"))) {
                            System.out.println("Action is forward to: " + target.toString());
                            forwardLog.add (msg);
                            ((NewDirective)directives[i]).
                                setDestination(new ClusterIdentifier(target.toString()));
                            msg.setTarget(target);
                        }
                    }
                }
            }
        }
        else if (actionIsAccept((Object)ruleBean.getValue())) {
            System.out.println("Action is accept");
            acceptLog.add(msg);                           
        }
        else if (actionIsSetAside((Object)ruleBean.getValue())) {
            MessageAddress target = new MessageAddress(newMessageDestination);
            if (msg instanceof DirectiveMessage) {
                Directive[] directives = ((DirectiveMessage)msg).getDirectives();
                for (int i=0; i<directives.length; i++) {
                    if (((DirectiveMessage)msg).getDirectives()[0] instanceof Task) {
                        Task task = (Task)((DirectiveMessage)msg).getDirectives()[0];
                        if (task.getVerb().equals(new Verb("Transport"))) {
                            System.out.println("Action is setAside");
                            setAsideLog.add(msg);
                            ((NewDirective)directives[i]).
                                setDestination(new ClusterIdentifier(target.toString()));
                            msg.setTarget(target);
                        }
                    }
                }
            }

        }

        return true; //success
    }

    private boolean actionIsForwardTo(Object o){
        System.out.println("In actionIsForwardTo");
        if (o instanceof String) {
            System.out.println("is a String");
            StringTokenizer tokens = new StringTokenizer((String)o, ":");
            if (tokens.hasMoreTokens()) {
                String next = tokens.nextToken();
                System.out.println("next is: " + next);
                System.out.println("FORWARD_TO is: " + FORWARD_TO);
                if (next.equals(FORWARD_TO)) {
                    newMessageDestination = tokens.nextToken();
                    System.out.println("1 newMessageDestination is: " + newMessageDestination);
                    return true;
                }
            }
        }
        System.out.println("2 newMessageDestination is: " + newMessageDestination);
       
        return false;
    }

    private boolean actionIsAccept(Object o){
        if (o instanceof String) {
            String str = (String) o;
            if (str.equals(ACCEPT)) {
                return true;
            }
        }
        return false;
    }

    private boolean actionIsSetAside(Object o){
        if (o instanceof String) {
            String str = (String) o;
            if (str.equals(SET_ASIDE))
                return true;
        }
        return false;
    }
    */

    // Message Integrity Level Processing

    protected void incomingMessageIntegrity(DirectiveMessage msg)
    {
	Directive[] d = msg.getDirectives();
//	TrustSet[] set = msg.getTrustSets();

	for(int i = 0; i < d.length; i++) {
//	    if(set[i] == null)set[i] = new TrustSet();
//	    incomingMessageIntegrity(d[i], set[i]);
	}
    }

    protected void incomingMessageIntegrity(Directive d, TrustSet set)
    {
	PolicyRuleBean policy = null;
	policy = 
	    (PolicyRuleBean)cache.get(AccessControlPolicy.IN_MSG_INTEGRITY,
				      d.getSource().toString());
	if(policy == null)	// agent and default policy not available
	    return;		// continue on to the next directive
	selectCriticality(policy, set);
    }

    protected void incomingMessageIntegrity(Message msg) 
    {
	PolicyRuleBean policy = null;
	policy = 
	    (PolicyRuleBean)cache.get(AccessControlPolicy.IN_MSG_INTEGRITY,
				      msg.getOriginator().toString());
	if(policy == null)	// agent and default policy not available
	    return;		// bail out of checking this message 
//	selectCriticality(policy, msg.getTrustSet());
    } 

    protected void outgoingMessageIntegrity(DirectiveMessage msg)
    {
	Directive[] d = msg.getDirectives();
//	TrustSet[] set = msg.getTrustSets();

	for(int i = 0; i < d.length; i++) {
//	    if(set[i] == null)set[i] = new TrustSet();
//	    incomingMessageIntegrity(d[i], set[i]);
	}
    }

    protected void outgoingMessageIntegrity(Directive d, TrustSet set)
    {
	PolicyRuleBean policy = null;
	policy = 
	    (PolicyRuleBean)cache.get(AccessControlPolicy.IN_MSG_INTEGRITY,
				      d.getDestination().toString());
	if(policy == null)	// agent and default policy not available
	    return;		// continue on to the next directive
	selectIntegrity(policy, set);
    }

    protected void outgoingMessageIntegrity(Message msg) 
    {
	PolicyRuleBean policy = null;
	policy = 
	    (PolicyRuleBean)cache.get(AccessControlPolicy.IN_MSG_INTEGRITY, 
				      msg.getTarget().toString());
	if(policy == null)	// agent and default policy not available
	    return;		// bail out of checking this message 
//	selectIntegrity(policy, msg.getTrustSet());
    } 

    protected void selectIntegrity(PolicyRuleBean policy, TrustSet set) 
    {
	IntegrityAttribute value = (IntegrityAttribute)policy.getValue();
	// if policy criticality is less than current value
	if(value.compareTo(set.getIntegrityLevel()) < 0) {
	    // reassign to lower level
	    set.addAttribute(new IntegrityAttribute(value)); 
	}	
	if(debug) {
	    System.out.println("MTSProxy: setting for agent " +
			       policy.getKey() + " is set to " + 
			       set.getIntegrityLevel().toString());
	}
    }

        
    protected void incomingMessageCriticality(DirectiveMessage msg)
    {
	Directive[] d = msg.getDirectives();
//	TrustSet[] set = msg.getTrustSets();

	for(int i = 0; i < d.length; i++) {
//	    if(set[i] == null)set[i] = new TrustSet();
//	    incomingMessageCriticality(d[i], set[i]);
	}
    }

    protected void incomingMessageCriticality(Directive d, TrustSet set)
    {
	PolicyRuleBean policy = null;
	MissionCriticality value = null;
	policy = 
	    (PolicyRuleBean)cache.get(AccessControlPolicy.IN_MSG_CRITICALITY, 
				      d.getSource().toString());
	if(policy == null)	// agent and default policy not available
	    return;		// continue on to the next directive
	selectCriticality(policy, set);
    }

    protected void incomingMessageCriticality(Message msg) 
    {
	PolicyRuleBean policy = null;
	MissionCriticality value = null;
	policy = 
	    (PolicyRuleBean)cache.get(AccessControlPolicy.IN_MSG_CRITICALITY, 
				      msg.getOriginator().toString());
	if(policy == null)	// agent and default policy not available
	    return;		// bail out of checking this message 
//	selectCriticality(policy, msg.getTrustSet());
    } 

    protected void outgoingMessageCriticality(DirectiveMessage msg)
    {
	Directive[] d = msg.getDirectives();
//	TrustSet[] set = msg.getTrustSets();

	for(int i = 0; i < d.length; i++) {
//	    if(set[i] == null)set[i] = new TrustSet();
//	    outgoingMessageCriticality(d[i], set[i]);
	}
    }

    protected void outgoingMessageCriticality(Directive d, TrustSet set)
    {
	PolicyRuleBean policy = null;
	policy = 
	    (PolicyRuleBean)cache.get(AccessControlPolicy.OUT_MSG_CRITICALITY,
				      d.getDestination().toString());
	if(policy == null)	// agent and default policy not available
	    return;		// continue on to the next directive
	selectCriticality(policy, set);
    }

    protected void outgoingMessageCriticality(Message msg) 
    {
	PolicyRuleBean policy = null;
	policy = 
	    (PolicyRuleBean)cache.get(AccessControlPolicy.OUT_MSG_CRITICALITY,
				      msg.getTarget().toString());
	if(policy == null)	// agent and default policy not available
	    return;		// bail out of checking this message 
//	selectCriticality(policy, msg.getTrustSet());
    } 

    protected void selectCriticality(PolicyRuleBean policy, TrustSet set) 
    {
	MissionCriticality value = (MissionCriticality)policy.getValue();
	// if policy criticality is less than current value
	if(value.compareTo(set.getMissionCriticality()) < 0) {
	    // reassign to lower level
	    set.addAttribute(new MissionCriticality(value)); 
	}	
	if(debug) {
	    System.out.println("MTSProxy: setting for agent " +
			       policy.getKey() + " is set to " +
			       set.getMissionCriticality().toString());
	}

    }
    
    public MessageLog getSetAsideLog() {  return setAsideLog; }

    public MessageLog getForwardLog() {   return forwardLog; }
    
    public MessageLog getAcceptLog() {    return acceptLog; }
  
    public MessageLog getOutgoingLog() {    return outLog; }

    
    private String messageToString(Message msg)
    {
        return("source is: " +
                msg.getOriginator().getAddress() + 
                " and destination is: " + msg.getTarget().getAddress() +
                " with the following trust attributes: " /*+
//                msg.getTrustSet().toString()*/);
    }

}
