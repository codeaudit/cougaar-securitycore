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
 * Created on May 08, 2002, 2:42 PM
 */

package org.cougaar.core.security.access;

import org.cougaar.core.component.BinderWrapper;
import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ComponentDescription;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.agent.AgentManagerForBinder;
import org.cougaar.core.agent.Agent;
import org.cougaar.core.agent.AgentBinder;
import org.cougaar.core.mts.AgentState;
import org.cougaar.core.mts.MessageTransportClient;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MisdeliveredMessageException;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.planning.ldm.plan.Directive;
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.core.blackboard.DirectiveMessage;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.core.security.services.acl.AccessControlPolicyService;
import org.cougaar.core.security.acl.trust.*;
import org.cougaar.core.security.policy.AccessControlPolicy;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.services.acl.*;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.monitoring.publisher.EventPublisher;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.MessageFailureEvent;

import java.util.*;

public class AccessAgentProxy
  implements MessageTransportService, MessageTransportClient
{
  private MessageTransportService mts;
  private MessageTransportClient mtc;
  private Object object;
  private SecurityPropertiesService secprop = null;
  private ServiceBroker serviceBroker;
  private LoggingService log;
  // event publisher to publish message failure
  private static EventPublisher eventPublisher = null;
  
  private static MessageAddress myID = null;
  private static AccessControlPolicyService acps;
  private static boolean debug = false;
  private static int infoLevel = 0;
  private static String SECURE_PROPERTY = 
  "org.cougaar.message.transport.secure";
  
  public AccessAgentProxy (MessageTransportService mymts,
			   Object myobj,
			   AccessControlPolicyService myacps,
			   ServiceBroker sb) {
    this.mts=mymts;
    this.object=myobj;
    acps=myacps;
    serviceBroker = sb;
    
    if (object instanceof Agent)
      myID = ((Agent)object).getAgentIdentifier();

    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class, null);
    if(log.isDebugEnabled())
      log.debug("Access agent proxy got init:=========>");
   
    
  }
  
  // static method used to initialize EventPublisher
  public static synchronized void addPublisher(EventPublisher publisher) {
    if(eventPublisher == null) {
      eventPublisher = publisher;
    }
  }
  
  /* ********************************************************
   *  BEGIN MessageTransportService implementation
   */
  public void sendMessage(Message message) {
    if(log.isDebugEnabled())
       log.debug(" Send message of access binder called :"+message.toString());
/*
    if(myID != null && message.getOriginator() != myID){
      //not suppose to happen
      publishMessageFailure(message.getOriginator().toString(),
                            message.getTarget().toString(),
                            MessageFailureEvent.INCONSISTENT_IDENTIFIER,
                            message.toString());
      if(log.isWarnEnabled()) {
        log.warn("Agent " + myID + " is rejecting outgoing message: " + message.toString());
      }
      return;
    }
*/      
    if(mts!=null) {
      TrustSet[] ts;
      ts = checkOutgoing(message);
      checkOutVerbs(message);
	
      if(ts==null) {
	      if(log.isWarnEnabled()) {
	        log.warn("Warning: rejecting outgoing message: " + 
		        ((message != null)? message.toString():
		        "Null Message"));
	      }
	      return;		// the message is rejected so we abort here
      }
      //making exceptions for SAFEMessage
      if(message instanceof safe.comm.SAFEMessage){
        mts.sendMessage(message);
        return;
      }
      MessageWithTrust mwt;
      mwt = new MessageWithTrust(message, ts);
      mts.sendMessage(mwt);
      if(log.isDebugEnabled()) {
	      log.debug("DONE sending Message from Access Agent proxy ====================>"+mwt.toString());
      }
    
    }
  }
  
  public void registerClient(MessageTransportClient client) {
    if(log.isDebugEnabled())
      log.debug(" registering client :============>");
    if(mts!=null) {
      mtc=client;
      mts.registerClient(this);
    }

  }
  
  public void unregisterClient(MessageTransportClient client) {
    if(log.isDebugEnabled())
      log.debug("un registering client :============>");
    if(mts!=null) {
      mtc=null;
      mts.unregisterClient(this);
    }
    
  }
  
  public ArrayList flushMessages() {
    ArrayList returndata=null;
    if(mts!=null)
      returndata=  mts.flushMessages();
    return returndata;
  }
  
  public String getIdentifier() {
   
    String identifier=null;
    if(mts!=null)
      identifier=mts.getIdentifier() ;
    return identifier;
  }

  public boolean addressKnown(MessageAddress a) {
   
    boolean addressKnown=false;
    if(mts!=null)
      addressKnown= mts.addressKnown(a); 
    return addressKnown;
  }
  
  public AgentState getAgentState() {
    AgentState as = null;
    if(mts!=null) {
      as = mts.getAgentState(); 
    }
    return as;
  }

  /* ********************************************************
   *  END MessageTransportService implementation
   */

  public MessageAddress getMessageAddress(){
    MessageAddress messageaddress=null;
    if(mtc!=null) {
      messageaddress=mtc.getMessageAddress();
    }
    return messageaddress;
  }
  
  public void receiveMessage(Message m)  {
    if(mtc!=null) {
      if(log.isDebugEnabled())
	      log.debug(" received message of Access agent proxy in :"
		      + getMessageAddress().toString() +"  :        "+ m.toString());
      if (m instanceof MessageWithTrust ) {
	      if(log.isDebugEnabled())
	        log.debug(" Got instance of MWT===================>");
	      MessageWithTrust mwt = (MessageWithTrust)m;
	      if (mwt == null) {
	        if(log.isWarnEnabled()) {
	          log.warn("WARNING: message to " + mtc.getMessageAddress().toString()
			        + " not delivered (null msg)");
	        }
	      }
	
	      Message contents =mwt.getMessage();
	      TrustSet tset[]=mwt.getTrusts();
	      if(contents==null) {
	        publishMessageFailure(m.getOriginator().toString(),
                                m.getTarget().toString(),
                                MessageFailureEvent.INVALID_MESSAGE_CONTENTS,
                                m.toString());
	        if(log.isWarnEnabled()) {
	          log.warn("WARNING: Rejecting incoming messagewithtrust as message contents are NULL: "
		          + m.toString());
	        }
	        return;
	      }
	
	      if(tset==null) {
	        mtc.receiveMessage(contents);
	        if(log.isDebugEnabled()) {
	          log.debug("receiving Message from Access Agent proxy ====================>");
	        }
	        return;
	      }
	
	      checkInVerbs(contents);
	      incomingTrust(contents, tset);
	      String failureIfOccurred = null;
	      if(!incomingMessageAction(contents, tset[0])) {
	        failureIfOccurred = MessageFailureEvent.SETASIDE_INCOMING_MESSAGE_ACTION;
	        if (log.isWarnEnabled())
	          log.warn("WARNING: Rejecting incoming messagewithtrust : "
		          + m.toString());
	      }
	      else if(!incomingAgentAction(contents)) {
	        failureIfOccurred = MessageFailureEvent.SETASIDE_INCOMING_AGENT_ACTION;
	        if (log.isWarnEnabled())
	          log.warn("WARNING: Rejecting incoming messagewithtrust : "
		          + m.toString());
	      }
	
	      if(failureIfOccurred != null) {
	        // a failure has occurred.  publish idmef message and return
	        publishMessageFailure(m.getOriginator().toString(),
                                m.getTarget().toString(),
                                failureIfOccurred,
                                m.toString());
	        return;
	      }
	      
	      if(log.isDebugEnabled()) {
	        log.debug("DONE receiving Message from Access Agent proxy ====================>"+ contents.toString());
	      }
	
	      mtc.receiveMessage(contents);
	      return;
      } 
      else if(m instanceof safe.comm.SAFEMessage){
        mtc.receiveMessage(m);
      } 
      else {
	      if (log.isErrorEnabled())
	        log.error("Not an MessageWithTrust: " + m);
	      return;
	    //deliverer.deliverMessage(m, dest);
      }
    }
  }
  
  /** removes the nth directive from a directive message */
  private  static boolean removeDirective(DirectiveMessage msg, int index) {
    Directive[] oldDirective = msg.getDirectives();
    if(oldDirective.length == 1){
      msg.setDirectives(new Directive[0]);
      //if(debug)
	    //System.out.println("WARNING: removing last directive.");
      return true;
    }
    
    Directive[] newDirective = new Directive[oldDirective.length - 1];
    
    int i;
    
    for(i = 0; i < index; i++) {
      newDirective[i] = oldDirective[i];
    }
    for(i = index ; i < newDirective.length; i++) {
      newDirective[i] = oldDirective[i + 1];
    }
    msg.setDirectives(newDirective);
    //if(debug)
      //System.out.println("WARNING: removed IN directive " +
			 //index);
    return false;
  }//removeDirective
 
  /**
   * Check verb-based policy
   * @param direction true: incoming message. false: outgoing message.
   */
  private static void checkMessage(Message msg, boolean direction) {
    //if (debug) {
      //System.out.println("Checking message:" + msg.getClass().toString());
    //}
    if(msg instanceof MessageWithTrust) {
      //System.out.println("MessageWithTrust  message:"+msg.toString());
      //System.out.println(direction ?"incomming message" :"outgoingMessage"); 
      if(msg instanceof DirectiveMessage) {
	//if(debug)
	  //System.out.println("Doing the check in DirectiveMessage of  checkMessage:");
	Directive directive[] =
	  ((DirectiveMessage)msg).getDirectives();
	int len = directive.length;
	for(int i = 0; i < len; i++) {
	  //if (debug) {
	    //System.out.println("Directive[" + i + "]:"
			//       + directive[i].getClass().toString());
	  //}
	  if(!(directive[i] instanceof Task))
	    continue;
	  Task task = (Task)directive[i];
	  String address = null;
	  boolean match = false;
	  //if(debug) {
	    //System.out.println("Processing task " + task.getVerb());
	  //}

	  match = matchVerb(task.getSource().toString(),
			    task.getDestination().toString(),
			    task.getVerb(), direction);
	  if(!match) {
	    if(removeDirective((DirectiveMessage)msg, i)) return;
	    directive = ((DirectiveMessage)msg).getDirectives();
	    len = directive.length;
	    i--;
	  }
	}
      }
      else if (msg.getClass().
	       getName().equals("safe.comm.SAFEMessage")) {
	// Silently ignore these messages
      }
      else {
	//if (debug) {
	  //System.out.println("Warning: unexpected message. Message Class:"
			    // + msg.getClass().getName());
	//}
	/* For test purposes only 
	   if (msg instanceof MoveCryptoMessage && direction) {
	   MoveCryptoMessage m = (MoveCryptoMessage) msg;
	   System.out.println("Received Transferable identity from "
	   + m.getOriginator().toAddress()
	   + " to " + m.getTarget().toAddress());
	   aiService.completeTransfer(m.getTransferableIdentity(),
	   m.getOriginator().toAddress(),
	   m.getTarget().toAddress());
	   }
	*/
      }
    }
    else {
      //if (debug) {
	//System.out.println("Warning: unexpected message. Message Class:"
			   //+ msg.getClass().getName());
      //}
    }
    
  }

  private static boolean matchVerb(String source, String target,
				   Verb verb, boolean direction)  {

    Object[] verbs = null;
    if (direction) {
      // Incoming message
      verbs = acps.getIncomingVerbs(source, target);
    }
    else {
      // Outgoing message
      verbs = acps.getOutgoingVerbs(source, target);
    }

    if( verbs[0].toString()=="ALL" ) {
      //if(debug) {
	//System.out.println("AccessControlProxy: got * verb, so blocking "
			   //+verb+" for " + source + "->" + target);
      //}
      return true;
    }

    if(verb == null || verbs.length == 0) {
      //if(debug)
      //System.out.println("AccessControlAspect: no out verbs for " 
      //			  + source + ", " + target + ", " + verb );
      return false;		// we have no policy so return
    }
    for(int i = 0; i < verbs.length; i++) {
      Verb v = null;
      try{
	v = (Verb)verbs[i];
      }
      catch(Exception e){
	//probably a cast error, quietly skip
      }
      if (v==null) continue;

      if(verb.equals(v)) {
	//if(debug)
        //System.out.println("AccessControlproxy: matched out verbs "
				    //+ verbs[i] + " == " + verb);
	return true;	// we found a match so return success
      }
    }
    return false;		// we found no matches so return false
  }
  
  private TrustSet[] checkOutgoing(Message msg) {
    if(msg == null) {
      return null;
    }
    String failureIfOccurred = null;
    TrustSet[] trust = null;
    trust = outgoingTrust(msg);
    if(!outgoingMessageAction(msg, trust[0])) {
      failureIfOccurred = MessageFailureEvent.SETASIDE_OUTGOING_MESSAGE_ACTION;
      trust = null;
    }
    else if(!outgoingAgentAction(msg)) {
      failureIfOccurred = MessageFailureEvent.SETASIDE_OUTGOING_AGENT_ACTION;
      trust = null;
    }
    if(failureIfOccurred != null) {
      publishMessageFailure(msg.getOriginator().toString(),
                            msg.getTarget().toString(),
                            failureIfOccurred,
                            msg.toString());
    }
    return trust;
  }

  private void compare(TrustSet msgSet, TrustSet policySet) {
    Iterator keys = policySet.keySet().iterator();
    while(keys.hasNext()) {
      String type = (String)keys.next();
      TrustAttribute msgAttribute = msgSet.getAttribute(type);
      TrustAttribute policyAttribute = policySet.getAttribute(type);
		
      try {
	if(policyAttribute.compareTo(msgAttribute) < 0)
	  msgSet.addAttribute(policyAttribute);
      }
      catch(Exception ex) {
	//ex.printStackTrace();
      }
    }
  }

  private TrustSet[] outgoingTrust(Message msg){
    TrustSet[] set = new TrustSet[1]; 
    TrustSet policySet;

    try {
      policySet = acps.getOutgoingTrust
	(msg.getOriginator().toString(), 
	 msg.getTarget().toString());
    }
    catch(Exception ex) {
      if(log.isDebugEnabled())
      log.debug("Warning: no msg outgoing trust for type = "
			 + msg.getClass());  
      return null;
    }
    if(policySet!=null){
      set[0] = policySet;
    }
    if(msg instanceof DirectiveMessage) {
      Directive directive[] = ((DirectiveMessage)msg).getDirectives();
      set = new TrustSet[directive.length+1];
      set[0] = policySet;
      TrustSet policy;

      for(int i = 0; i < directive.length; i++) {
	policy = acps.getOutgoingTrust
	  (directive[i].getSource().toString(),
	   directive[i].getDestination().toString());
	if(set[i+1] == null){
	  set[i+1] = policy;
	}else{
	  if(directive[i] instanceof Task) {
	    Task task = (Task)directive[i];
	    set[i+1] = policy;
	  } else
	    compare(set[i+1], policy);
	}
    
      }
        
    }
    return set;
  }  

  private void checkOutVerbs(Message msg) {
    checkMessage(msg, false);
  }
      
  private boolean outgoingAgentAction(Message msg) {
    String action;

    try {
      action = acps.getOutgoingAgentAction
	(msg.getOriginator().toString(), msg.getTarget().toString());
    }
    catch(Exception ex) {
      if(log.isDebugEnabled())
      log.debug("Warning: no access control for message type "
			 + msg.getClass());
      return true;
    }
    if(action == null) {
      if(log.isDebugEnabled())
        log.debug("AccessControlProxy: no action(out) set");
      return true;
    }

    if(log.isDebugEnabled())
      log.debug("AccessControlProxy: action(out) = " + action);
    
    if(msg instanceof DirectiveMessage)
      return outgoingAgentAction((DirectiveMessage)msg) &
	action.equals(AccessControlPolicy.ACCEPT);
    return action.equals(AccessControlPolicy.ACCEPT);
  }

  private boolean outgoingAgentAction(DirectiveMessage msg) {
    String action = null;
    Directive directive[] = 
      ((DirectiveMessage)msg).getDirectives();
    int len = directive.length;

    for(int i = 0; i < len; i++) {
      if(!(directive[i] instanceof Task))
	continue;
      Task task = (Task)directive[i];
      action = acps.getOutgoingAgentAction
	(task.getSource().toString(), 
	 task.getDestination().toString());
      if(action == null)
	continue;
      if(action.equals(AccessControlPolicy.SET_ASIDE)){

	if(removeDirective((DirectiveMessage)msg, i)) return false;
	if(msg == null) return false;
	directive = ((DirectiveMessage)msg).getDirectives();
	len = directive.length;
	i--;
      }
    }
  if(log.isDebugEnabled())
    log.debug("AccessControlProxy: DirectiveMessage now contains " + 
				msg.getDirectives().length + 
				" directives.");
    //return (msg.getDirectives().length > 0);
    return true;
  }

  /**
   */
  private boolean outgoingMessageAction(Message msg, TrustSet trust) {
    String act;
    
    try {
      String msgOrigin = msg.getOriginator().toString();
      String trustValue = (String)trust.getAttribute(MissionCriticality.name).getValue();
      act = acps.getOutgoingAction(msgOrigin, trustValue);
    }
    catch(Exception ex) {
      if(log.isDebugEnabled())
        log.debug("AccessControlProxy: Warning: no access control for msg"
			 + msg);
      return true;
    }
    if(act == null) {
      if(log.isDebugEnabled())
        log.debug("AccessControlProxy: No action(out) set");
      
      return true;
    }
      if(log.isDebugEnabled())
        log.debug("AccessControlProxy: action(out) = " + act);
    
    return (!act.equals(AccessControlPolicy.SET_ASIDE));
  }
  
  private void checkInVerbs(Message msg) {
    checkMessage(msg, true);
  }

  private void incomingTrust(Message msg, TrustSet[] set) {
    TrustSet policySet;
    try {
      policySet = acps.getIncomingTrust
	(msg.getOriginator().toString(), msg.getTarget().toString());
    }
    catch(Exception ex) {
      if(log.isDebugEnabled())
        log.debug("Warning: no msg incoming trust for type = "
			 + msg.getClass());  
      return;
    }
    if(policySet!=null){
      compare(set[0], policySet);
    }
    if(msg instanceof DirectiveMessage) {
      Directive directive[] = ((DirectiveMessage)msg).getDirectives();
      TrustSet policy;
      
      if (directive==null) return;
      if (set.length < directive.length+1){
	for (int j = 0; j < directive.length - set.length + 1; j++){
	  set[j+set.length] = new TrustSet();
	  //set[j+set.length] = null;
	}
      }
      for(int i = 0; i < directive.length; i++) {
	policy = acps.getIncomingTrust
	  (directive[i].getSource().toString(),
	   directive[i].getDestination().toString());
	if(set[i+1] == null){
	  set[i+1] = policy; //new TrustSet();
	}else{
	  if(directive[i] instanceof Task) {
	    Task task = (Task)directive[i];
	    set[i+1] = policy;
	  } else {
	    compare(set[i+1], policy);
	  }
	}
      }
    }
  }
	
  private boolean incomingAgentAction(Message msg) {
    String action;

    try {
      action = acps.getIncomingAgentAction
	(msg.getOriginator().toString(), msg.getTarget().toString());
    }
    catch(Exception ex) {
      if(log.isDebugEnabled())
        log.debug("Warning: no access control for message type "
			 + msg.getClass());
      return true;
    }
    if(log.isDebugEnabled())
      log.debug("AccessControlProxy: action(in) = "
				+ action);
    if(action == null)
      return true;
    if(msg instanceof DirectiveMessage)
      return incomingAgentAction((DirectiveMessage)msg) &
	!action.equals(AccessControlPolicy.SET_ASIDE);
    return (!action.equals(AccessControlPolicy.SET_ASIDE));
  }
  
  private boolean incomingAgentAction(DirectiveMessage msg) {
    String action = null;
    Directive directive[] = 
      ((DirectiveMessage)msg).getDirectives();
    int len = directive.length;
    
    for(int i = 0; i < len; i++) {
      if(!(directive[i] instanceof Task))
	continue;
    if(log.isDebugEnabled())
      log.debug("AccessControlProxy: processing in task " + i);
      Task task = (Task)directive[i];
      action = acps.getIncomingAgentAction
	(task.getSource().toString(), task.getDestination().toString());
      if(action == null)
	continue;
      if(action.equals(AccessControlPolicy.SET_ASIDE)){
	
	if(removeDirective(msg, i)) return false;
	directive = ((DirectiveMessage)msg).getDirectives();
	len = directive.length;
	i=i--;
      }
    }
    return true;
  }
	
  private boolean incomingMessageAction(Message msg, TrustSet t) {
    String action;
    try {
      action = acps.getIncomingAction
	(msg.getTarget().toString(),
	 (String)t.getAttribute(MissionCriticality.name).getValue());
    }
    catch(Exception ex) {
      if(log.isDebugEnabled())
        log.debug("Warning: no access control for message" + msg);
      return true;
    }
    if(debug) {
      if(log.isDebugEnabled())
        log.debug("AccessControlProxy: action(in) = "	 + action);
    }
    if(action == null)
      return true;
    return (!action.equals(AccessControlPolicy.SET_ASIDE));
  }
  
  /**
   * publish a message failure event
   */
  private void publishMessageFailure(String source, String target,
    String reason, String data) {
    FailureEvent event = new MessageFailureEvent(source,
                                                 target,
                                                 reason,
                                                 data);
    if(eventPublisher != null) {
      eventPublisher.publishEvent(event); 
    }
    else {
      if(log.isDebugEnabled()) {
        log.debug("EventPublisher uninitialized, unable to publish event:\n" + event);
      }
    }  
  }
}
