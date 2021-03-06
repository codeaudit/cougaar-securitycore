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

package org.cougaar.core.security.access.message;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.cougaar.community.manager.Request;
import org.cougaar.core.agent.Agent;
import org.cougaar.core.blackboard.Directive;
import org.cougaar.core.blackboard.DirectiveMessage;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.AgentState;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageTransportClient;
import org.cougaar.core.relay.RelayDirective;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.MessageFailureEvent;
import org.cougaar.core.security.monitoring.publisher.SecurityEventPublisher;
import org.cougaar.core.security.policy.enforcers.WPEnforcer;
import org.cougaar.core.security.policy.builder.VerbBuilder;
import org.cougaar.core.security.services.policy.PolicyService;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.core.wp.resolver.WPQuery;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public abstract class AccessAgentProxy implements MessageTransportService,
  MessageTransportClient, MessageAccess {

  protected transient MessageTransportService mts;

  protected transient MessageTransportClient  mtc;

  protected transient Object                  object;

  protected transient ServiceBroker           serviceBroker;

  protected transient LoggingService          log;

  protected transient MessageAddress          myID        = null;

  protected transient PolicyService           policyService;

  protected transient WPEnforcer              _wpEnforcer = null;
  
  public AccessAgentProxy(MessageTransportService mymts, Object myobj,
                          PolicyService ps, ServiceBroker sb ) {
    this.mts = mymts;
    this.object = myobj;
    serviceBroker = sb;
    log = (LoggingService) serviceBroker.getService(this, LoggingService.class,
                                                    null);
    policyService = (PolicyService) serviceBroker.getService(this,
                                                             PolicyService.class, null);
    if(policyService == null){
      if(log.isDebugEnabled()){
        log.debug("Policy service is not ready yet in Access Agent Proxy ");
      }
    }
    if (object instanceof Agent) {
      myID = ((Agent) object).getAgentIdentifier();
    }
    else {
      if(log.isDebugEnabled()) {
        log.debug("Object is not instance of Agent"+ myobj.getClass().getName());
      }
    }

    _wpEnforcer = new WPEnforcer(sb);
    try {
      _wpEnforcer.registerEnforcer();
    }
    catch (Exception e) {
      _wpEnforcer = null;
      if (log.isWarnEnabled()) {
        log.warn("Guard not available. Running without policy");
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("Access agent proxy for " + myID + " initialized");
    }
  }

  /***************************************************************************
   * BEGIN MessageTransportService implementation
   */

  /**
   * Send a message to the Message transport layer.
   * 
   * @param message -
   *          The message to send.
   */
  public void sendMessage( Message message ) {
    if (log.isDebugEnabled()) {
      log.debug("SendMessage: " + message.toString());
    }

    if (myID != null && !message.getOriginator().equals(myID)) {
      //not suppose to happen
      publishMessageFailure(message.getOriginator().toString(), message
                            .getTarget().toString(), MessageFailureEvent.INCONSISTENT_IDENTIFIER,
                            message.toString());
      if (log.isWarnEnabled()) {
        log.warn("Agent " + myID + " is rejecting outgoing message: "
                 + message.toString());
      }
      return;
    }

    if (mts != null) {
      boolean tossMessage = checkOutVerbs(message);
      if (tossMessage) {
        if (log.isWarnEnabled()) {
          log.warn("Rejecting outgoing message: " + message);
        }
        // message failure notifications are done in checkMessage()
        return;
      }

      /*
       * TODO: the following "if" test is a big kludge, due to the fact
       * node agents can have binders, so we are making exceptions--no
       * wrapping with TrustSet--for node agents. Once Bugzilla #2103 is
       * addressed remember to take this out.
       * 
       * REMOVED for 10.2 port - mluu
       */
      /*
       * TrustSet[] ts; ts = checkOutgoing(message);
       * 
       * if(ts==null) { if(log.isWarnEnabled()) { log.warn("Rejecting
       * outgoing message: " + message); } return; // the message is
       * rejected so we abort here } MessageWithTrust mwt; mwt = new
       * MessageWithTrust(message, ts); mts.sendMessage(mwt);
       * if(log.isDebugEnabled()) { log.debug("DONE sending Message from
       * Access Agent proxy" +mwt.toString()); }
       */
      mts.sendMessage(message);
    }//if(mts!=null)
  }

  public void registerClient( MessageTransportClient client ) {
    if (log.isDebugEnabled()) {
      log.debug("Registering client: "
                + client.getMessageAddress().toAddress());
    }
    if (mts != null) {
      mtc = client;
      mts.registerClient(this);
    }
    if(myID== null){
      myID=client.getMessageAddress();
    }
  }

  public void unregisterClient( MessageTransportClient client ) {
    if (log.isDebugEnabled()) {
      log.debug("un registering client" + client.getMessageAddress().toAddress());
    }
    if (mts != null) {
      mts.unregisterClient(this);
      mtc = null;
    }
  }

  public ArrayList flushMessages() {
    ArrayList returndata = null;
    if (mts != null) {
      returndata = mts.flushMessages();
    }
    return returndata;
  }

  public String getIdentifier() {

    String identifier = null;
    if (mts != null) {
      identifier = mts.getIdentifier();
    }
    return identifier;
  }

  public boolean addressKnown( MessageAddress a ) {

    boolean addressKnown = false;
    if (mts != null) {
      addressKnown = mts.addressKnown(a);
    }
    return addressKnown;
  }

  public AgentState getAgentState() {
    AgentState as = null;
    if (mts != null) {
      as = mts.getAgentState();
    }
    return as;
  }

  /***************************************************************************
   * END MessageTransportService implementation
   */

  /***************************************************************************
   * BEGIN MessageTransportClient implementation
   */
  public MessageAddress getMessageAddress() {
    MessageAddress messageaddress = null;
    if (mtc != null) {
      messageaddress = mtc.getMessageAddress();
    }
    return messageaddress;
  }

  public long getIncarnationNumber() {
    return (mtc == null ? 0 : mtc.getIncarnationNumber());
  }

  public void receiveMessage( final Message m ) {
    if (mtc == null) {
      log.warn("Message Transport Client is null for: " + m + " on the agent:"
               + myID);
      return;
    }
    if (log.isDebugEnabled()) {
      log.debug("receiveMessage: " + getMessageAddress().toString() + " : "
               + m.toString());
    }
    /**
     * In older version of AccessAgent proxy which use to be in org.cougaar.core.security.access 
     * Receive message method has if(true) and else. Else will never get executed but it was there. 
     * In the else block of code it would check if the message was 
     * wrapped in MessageWithTrust and it would check the trust but since i'm not sure if that part 
     * is used or not.   
     */
    //if (true) {
    // Check verb of incoming message
    boolean tossMessage = checkInVerbs(m);

    if (tossMessage) {
      if (log.isWarnEnabled()) {
        log.warn("Rejecting incoming message: " + m);
      }
      // message failure notifications are done in checkMessage()
      return;
    }
    
    // Receive message
    mtc.receiveMessage(m);
    //}
  }
  /***************************************************************************
   * END MessageTransportClient implementation
   */
  
  abstract boolean isMessageDenied( String source, String target, String verb,
                                    boolean direction );
 
  abstract Set getAllowedVerbs(String source, String target); 

  /*private boolean checkMessage( Message msg, boolean direction ) {
    if (log.isDebugEnabled()) {
    log.debug("checkMessage(" + msg + "), class " + msg.getClass().getName()
    + ", direction " + direction);
    }
    String source = msg.getOriginator().toString();
    String target = msg.getTarget().toString();
    if (msg instanceof DirectiveMessage) {
    return checkDirectiveMessage(source, target, msg, direction);
    }

    if (msg instanceof WPQuery) {
    // first still need to know whether source and target are allowed to talk
    if (!isMessageDenied(source, target, null, direction)) {
    return checkWPQueryMessage(target, (WPQuery) msg);
    }
    }
    return isMessageDenied(source, target, null, direction);
    }*/
  protected boolean checkDirectiveMessage( String source, String target,
                                           Message msg, boolean direction ) {

    DirectiveMessage dmsg = (DirectiveMessage) msg;
    Directive directive[] = dmsg.getDirectives();
    int len = directive.length;
    int newLen = len;

    long now = 0;
    if (log.isInfoEnabled()) {
      now = System.currentTimeMillis();
      log.info("Message has " + len + " directives");
    }
    // Get the list of allowed verbs.
    Set allowedVerbs = getAllowedVerbs(source, target);
    for (int i = 0; i < len; i++) {
      /*
       * Modified by Rakesh Modified the code to check directive source
       * with message source and ignore the target directives as the
       * target directive will be an ABA
       */
      if (!directive[i].getSource().toString().equals(source)) {
        if (log.isDebugEnabled()) {
          log.debug(" Source at directive is :"
                  + directive[i].getSource().toString());
          log.debug(" Source is  in message :" + source);
        }
        publishMessageFailure(source, target,
                              MessageFailureEvent.SOURCE_ADDRESS_MISMATCH, dmsg.toString());

        directive[i] = null;
        newLen--;
      } 
      else if (directive[i] instanceof RelayDirective && direction) {
        // only consider incoming messages
        Object relay = null;
        if (directive[i] instanceof RelayDirective.Add) {
          relay = ((RelayDirective.Add) directive[i]).getContent();
        } else if (directive[i] instanceof RelayDirective.Change) {
          // do we need to handle a change
          relay = ((RelayDirective.Change) directive[i]).getContent();
        }

        // check if this is a CommunityManager Request
        if (relay != null && relay instanceof Request) {
          Request cmr = (Request) relay;
          if (log.isDebugEnabled()) {
            log.debug("CommunityManager Request from " + source);
            log.debug(cmr.toString());
          }
          /*
            System.out.println("CommunityManager Request from "
            + source + " -> " + target);
            System.out.println(cmr.toString());
          */
          if (!CommunityServiceUtil.isRequestValid(cmr, source)) {
            // log invalid community request message failure
            log.warn("Rejecting invalid commmunty manager request from "
                     + source);
            publishMessageFailure(source, target,
                                  MessageFailureEvent.INVALID_COMMUNITY_REQUEST, cmr.toString());
            // remove invalid community request directive from message
            directive[i] = null;
            newLen--;
          }
        }
      } else {
        String verb = null;
        if (directive[i] instanceof Task) {
          if(log.isDebugEnabled()){
            log.debug("Directive at "+ i + "Instance of task");
          }
          Task task = (Task) directive[i];
          Verb verbV = task.getVerb();
          if (verbV != null) {
            if(log.isDebugEnabled()){
              log.debug("Directive casted to verb and verb "+ verbV.toString());
            }
            verb = verbV.toString();
          }
        }
        if(log.isDebugEnabled()){
          log.debug("Directive calling isMessageDenied ");
        }
        // Is verb allowed?
        String kaosVerb = VerbBuilder.kaosVerbFromVerb(verb);
        boolean allowed = ((allowedVerbs != null) && allowedVerbs.contains(kaosVerb));

        //boolean denied = isMessageDenied(source, target, verb, direction);
        if (!allowed) {
          if (log.isDebugEnabled()) {
            log.debug("Stripping task with verb " + verb);
          }
          publishMessageFailure(source, target,
                                MessageFailureEvent.VERB_DENIED, directive[i].toString());
          directive[i] = null;
          newLen--;
        }
      }
    }

    if (log.isInfoEnabled()) {
      log.info("checkDirectiveMessage in " + (System.currentTimeMillis() - now) + "ms");
    }

    if (newLen == 0) {
      // We've stripped the entire thing. Don't send this message.
      return true;
    }

    if (newLen != len) {
      Directive newDirectives[] = new Directive[newLen];
      int j = 0;
      for (int i = 0; i < len; i++) {
        if (directive[i] != null) {
          newDirectives[j++] = directive[i];
        }
      }
      dmsg.setDirectives(newDirectives);
    }
    return false;
  }

  protected  boolean checkWPQueryMessage(String target, WPQuery wpMsg) {
    // get where the agent really is, not from the source
    Map map = wpMsg.getMap();
    if(map== null){
      return false;
    }
    // the map contains (name, query)
    Iterator it = map.keySet().iterator();
    String agent = (String)it.next();
    if (log.isDebugEnabled()) {
      log.debug("checkWPQueryMessage: " + agent + " action: " + wpMsg.getAction());
    }
    // allowed if not using DAML
    if (_wpEnforcer == null) {
      return false;
    }

    /*
      String action = "Add";
      if (wpMsg.getAction() != WPQuery.MODIFY) {
      return false;
      }
      return !_wpEnforcer.isActionAuthorized(agent, agent, action);
    */
    if (wpMsg.getAction() == WPQuery.MODIFY) {
      return !_wpEnforcer.WPUpdateOk(agent, agent);
    }
    else if (wpMsg.getAction() == WPQuery.FORWARD) {
      return !_wpEnforcer.WPForwardOk(agent, target);
    }
    else if (wpMsg.getAction() == WPQuery.LOOKUP) {
      return !_wpEnforcer.WPLookupOk(agent);
    }
    else if (wpMsg.getAction() == WPQuery.PING) {
      return !_wpEnforcer.WPLookupOk(agent);
    }

    log.error("Unknown WP action: " + wpMsg.getAction());
    return true;
  }
   
  

  /**
   * publish a message failure event
   */
  protected void publishMessageFailure( String source, String target,
                                        String reason, String data ) {
    FailureEvent event = new MessageFailureEvent(source, target, reason, data);
    /*
     * if(eventPublisher != null) { eventPublisher.publishEvent(event); }
     * else { if(log.isDebugEnabled()) { log.debug("EventPublisher
     * uninitialized, unable to publish event:\n" + event); } }
     */
    SecurityEventPublisher.publishEvent(event);
  }

  protected boolean checkMessage(Message msg, boolean direction){
    if (log.isDebugEnabled()) {
      log.debug("checkMessage(" + msg + "), class " + msg.getClass().getName() + ", direction " + direction);
    }
    String source = msg.getOriginator().toString();
    String target = msg.getTarget().toString();
    if (msg instanceof DirectiveMessage) {
      if (log.isDebugEnabled()) {
        log.debug("checkMessage calling checkDirectiveMessage");
      }
      return checkDirectiveMessage(source, target, msg, direction);
    }
  
    if (msg instanceof WPQuery) {
      if (log.isDebugEnabled()) {
        log.debug("checkMessage calling is message denied ");
      }
      // first still need to know whether source and target are allowed to talk
      if (!isMessageDenied(source, target, null, direction)) {
        if (log.isDebugEnabled()) {
          log.debug("checkMessage calling checkWPQueryMessage");
        }
        return checkWPQueryMessage(target, (WPQuery)msg);
      }
    }
    return isMessageDenied(source, target, null, direction);
  }
  protected boolean checkInVerbs(Message msg) {
    return checkMessage(msg, true);
  }
  protected boolean checkOutVerbs(Message msg) {
    return checkMessage(msg, false);
  }
       
  public String getName(){
    return this.myID.toString();
  }
 
 
}
