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

import java.util.Iterator;

import org.cougaar.community.manager.Request;
import org.cougaar.core.blackboard.Directive;
import org.cougaar.core.blackboard.DirectiveMessage;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.Message;
import org.cougaar.core.relay.RelayDirective;
import org.cougaar.core.security.acl.trust.IntegrityAttribute;
import org.cougaar.core.security.acl.trust.MissionCriticality;
import org.cougaar.core.security.acl.trust.TrustAttribute;
import org.cougaar.core.security.acl.trust.TrustSet;
import org.cougaar.core.security.monitoring.event.MessageFailureEvent;
import org.cougaar.core.security.policy.AccessControlPolicy;
import org.cougaar.core.security.policy.mediator.XmlMessagePolicyMediator;
import org.cougaar.core.security.services.policy.PolicyService;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.core.wp.resolver.WPQuery;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.planning.ldm.plan.Verb;

public class XmlMessageAccessAgentProxy extends AccessAgentProxy {

  protected transient XmlMessagePolicyMediator messageMediator;

  public XmlMessageAccessAgentProxy(MessageTransportService mymts,
                                    Object myobj, PolicyService ps, ServiceBroker sb) {
    super(mymts, myobj, ps, sb);

  }

  boolean isMessageDenied(String source, String target, String verb,
                          boolean direction) {
    if (verb == null) {
      // only DAML policy handles no verb case
      return false;
    }

    Object[] verbs = null;
    if (direction) {
      // Incoming message
      verbs = messageMediator.getIncomingVerbs(source, target);
    } else {
      // Outgoing message
      verbs = messageMediator.getOutgoingVerbs(source, target);
    }

    if (verb == null || verbs.length == 0) {
      if (log.isDebugEnabled()) {
        log.debug("Unable to find verb:" + verb + " in policy:"
                  + verbs);
      }
      return false; // we have no policy so return
    }

    if (verbs[0].equals("ALL")) {
      log.debug("ALL are kept.");
      return false; //all allowed, no removal.
    }

    for (int i = 0; i < verbs.length; i++) {
      if (verb.equals(verbs[i])) {
        if (log.isDebugEnabled()) {
          log.debug("found verb to keep:" + verbs[i] + " for "
                    + source + "->" + target);
        }
        return false;
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("found unwanted verb:" + verb + " for " + source + "->"
                + target);
    }
    return true;
  }

  private void compare(TrustSet msgSet, TrustSet policySet) {
    if (msgSet == null) {
      msgSet = makeLowestTrust();
    }
    if (policySet == null || policySet.keySet() == null) {
      // TODO WHAT TO DO HERE?
      return;
    }
    Iterator keys = policySet.keySet().iterator();
    while (keys.hasNext()) {
      String type = (String) keys.next();
      TrustAttribute msgAttribute = msgSet.getAttribute(type);
      TrustAttribute policyAttribute = policySet.getAttribute(type);

      try {
        if (policyAttribute.compareTo(msgAttribute) < 0) {
          msgSet.addAttribute(policyAttribute);
        }
      } catch (Exception ex) {
        log.warn("Unable to compare message against policy: " + ex);
      }
    }
  }

  private TrustSet[] outgoingTrust(Message msg) {
    TrustSet[] set = new TrustSet[1];
    TrustSet policySet;

    try {
      policySet = messageMediator.getOutgoingTrust(msg.getOriginator()
                                                   .toString(), msg.getTarget().toString());
    } catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("No msg outgoing trust for type = " + msg.getClass());
      }
      return null;
    }
    if (policySet != null) {
      set[0] = policySet;
    }
    if (msg instanceof DirectiveMessage) {
      Directive directive[] = ((DirectiveMessage) msg).getDirectives();
      set = new TrustSet[directive.length + 1];
      set[0] = policySet;
      TrustSet policy;

      for (int i = 0; i < directive.length; i++) {
        policy = messageMediator.getOutgoingTrust(directive[i]
                                                  .getSource().toString(), directive[i].getDestination()
                                                  .toString());
        if (set[i + 1] == null) {
          set[i + 1] = policy;
        } else {
          if (directive[i] instanceof Task) {
            Task task = (Task) directive[i];
            set[i + 1] = policy;
          } else {
            compare(set[i + 1], policy);
          }
        }
      }
    }
    return set;
  }

    
  private boolean outgoingAgentAction(Message msg) {
    String action;

    try {
      action = messageMediator.getOutgoingAgentAction(msg.getOriginator()
                                                      .toString(), msg.getTarget().toString());
    } catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("No access control for message type " + msg.getClass()
                 + ". reason:" + ex);
      }
      return true;
    }
    if (action == null) {
      if (log.isDebugEnabled()) {
        log.debug("AccessControlProxy: no action(out) set");
      }
      return true;
    }

    if (log.isDebugEnabled()) {
      log.debug("AccessControlProxy: action(out) = " + action);
    }
    if (msg instanceof DirectiveMessage) {
      return outgoingAgentAction((DirectiveMessage) msg)
        & action.equals(AccessControlPolicy.ACCEPT);
    }
    return action.equals(AccessControlPolicy.ACCEPT);
  }

  private boolean outgoingAgentAction(DirectiveMessage msg) {
    String action = null;
    Directive directive[] = ((DirectiveMessage) msg).getDirectives();
    int len = directive.length;

    for (int i = 0; i < len; i++) {
      if (!(directive[i] instanceof Task)) {
        continue;
      }
      Task task = (Task) directive[i];
      action = messageMediator.getOutgoingAgentAction(task.getSource()
                                                      .toString(), task.getDestination().toString());
      if (action == null) {
        continue;
      }
      if (action.equals(AccessControlPolicy.SET_ASIDE)) {
        if (removeDirective((DirectiveMessage) msg, i)) {
          return false;
        }
        if (msg == null) {
          return false;
        }
        directive = ((DirectiveMessage) msg).getDirectives();
        len = directive.length;
        i--;
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("AccessControlProxy: DirectiveMessage now contains "
                + msg.getDirectives().length + " directives.");
    }
    //return (msg.getDirectives().length > 0);
    return true;
  }

  /**
   */
  private boolean outgoingMessageAction(Message msg, TrustSet trust) {
    String act;

    if (msg == null || msg.getOriginator() == null || trust == null) {
      // can't go on, drop the message.
      if (log.isWarnEnabled()) {
        log.warn("invalid input to outgoingMessageAction " + msg);
      }
      return false;
    }
    try {
      String msgOrigin = msg.getOriginator().toString();
      TrustAttribute mc = trust.getAttribute(MissionCriticality.name);
      if (mc == null) {
        // can't go on, drop the message.
        if (log.isWarnEnabled()) {
          log
            .warn("can't find MissionCriticality in outgoing message. "
                  + msg);
        }
        return false;
      }
      Object v = mc.getValue();
      if (v == null) {
        // can't go on, drop the message.
        if (log.isWarnEnabled()) {
          log
            .warn("can't find MissionCriticality in outgoing message. "
                  + msg);
        }
        return false;
      }
      act = messageMediator.getOutgoingAction(msgOrigin, v.toString());
    } catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("no access control for msg " + msg + ". reason:" + ex);
      }
      return false;
    }
    if (act == null) {
      if (log.isWarnEnabled()) {
        log.warn("No action(out) set for the message: " + msg);
      }
      return false;
    }
    if (log.isDebugEnabled()) {
      log.debug("AccessControlProxy: action(out) = " + act);
    }
    return (!act.equals(AccessControlPolicy.SET_ASIDE));
  }

   

  private boolean incomingTrust(Message msg, TrustSet[] set) {
    TrustSet policySet;
    try {
      policySet = messageMediator.getIncomingTrust(msg.getOriginator()
                                                   .toString(), msg.getTarget().toString());
    } catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("No msg incoming trust for type = " + msg.getClass());
      }
      return false;
    }
    if (policySet != null) {
      //for non-directive messages set length is 1.
      compare(set[0], policySet);
    }

    //for directive messages it's more complicated.
    if (msg instanceof DirectiveMessage) {
      Directive directive[] = ((DirectiveMessage) msg).getDirectives();
      TrustSet policy;

      if (directive == null) {
        return false;
      }
      if (set.length < directive.length + 1) {
        for (int j = 0; j < directive.length - set.length + 1; j++) {
          set[j + set.length] = new TrustSet();
          //set[j+set.length] = null;
        }
      }
      for (int i = 0; i < directive.length; i++) {
        policy = messageMediator.getIncomingTrust(directive[i]
                                                  .getSource().toString(), directive[i].getDestination()
                                                  .toString());
        if (set[i + 1] == null) {
          set[i + 1] = policy; //new TrustSet();
        } else {
          if (directive[i] instanceof Task) {
            Task task = (Task) directive[i];
            set[i + 1] = policy;
          } else {
            compare(set[i + 1], policy);
          }
        }
      }
    }
    return true;
  }

  private boolean incomingAgentAction(Message msg) {
    String action;

    try {
      action = messageMediator.getIncomingAgentAction(msg.getOriginator()
                                                      .toString(), msg.getTarget().toString());
    } catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("No access control for message type " + msg.getClass()
                 + ". reason:" + ex);
      }
      return true;
    }
    if (log.isDebugEnabled()) {
      log.debug("AccessControlProxy: action(in) = " + action);
    }
    if (action == null) {
      return true;
    }
    if (msg instanceof DirectiveMessage) {
      return incomingAgentAction((DirectiveMessage) msg)
        & !action.equals(AccessControlPolicy.SET_ASIDE);
    }
    return (!action.equals(AccessControlPolicy.SET_ASIDE));
  }

  private boolean incomingAgentAction(DirectiveMessage msg) {
    String action = null;
    Directive directive[] = ((DirectiveMessage) msg).getDirectives();
    int len = directive.length;

    for (int i = 0; i < len; i++) {
      if (!(directive[i] instanceof Task)) {
        continue;
      }
      if (log.isDebugEnabled()) {
        log.debug("AccessControlProxy: processing in task " + i);
      }
      Task task = (Task) directive[i];
      action = messageMediator.getIncomingAgentAction(task.getSource()
                                                      .toString(), task.getDestination().toString());
      if (action == null) {
        continue;
      }
      if (action.equals(AccessControlPolicy.SET_ASIDE)) {
        if (removeDirective(msg, i)) {
          return false;
        }
        directive = ((DirectiveMessage) msg).getDirectives();
        len = directive.length;
        i = i--;
      }
    }
    return true;
  }

  private boolean incomingMessageAction(Message msg, TrustSet trust) {
    String action;
    if (msg == null || trust == null) {
      // can't go on, drop the message.
      if (log.isWarnEnabled()) {
        log.warn("invalid input to incomingMessageAction " + msg);
      }
      return false;
    }
    try {
      TrustAttribute mc = trust.getAttribute(MissionCriticality.name);
      if (mc == null) {
        // can't go on, drop the message.
        if (log.isWarnEnabled()) {
          log
            .warn("can't find MissionCriticality in imcoming message. "
                  + msg);
        }
        return false;
      }
      Object v = mc.getValue();
      if (v == null) {
        // can't go on, drop the message.
        if (log.isWarnEnabled()) {
          log
            .warn("can't find MissionCriticality in imcoming message. "
                  + msg);
        }
        return false;
      }
      action = messageMediator.getIncomingAction(msg.getTarget()
                                                 .toString(), v.toString());
    } catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("No access control for message: " + msg + ". reason:"
                 + ex);
      }
      return false;
    }
    if (log.isDebugEnabled()) {
      log.debug("action(in) = " + action);
    }
    if (action == null) {
      if (log.isWarnEnabled()) {
        log.warn("No action(in) set for the message:" + msg);
      }
      return false;
    }
    return (!action.equals(AccessControlPolicy.SET_ASIDE));
  }
  private TrustSet makeLowestTrust() {
    TrustSet ts = new TrustSet();
    //range 1-5, 3 is default
    MissionCriticality mc = new MissionCriticality(3);
    ts.addAttribute(mc);
    //range 1-10, set to lowest.
    IntegrityAttribute ia = new IntegrityAttribute(1);
    ts.addAttribute(ia);
    return ts;
  }
  /** removes the nth directive from a directive message */
  private boolean removeDirective(DirectiveMessage msg, int index) {
    Directive[] oldDirective = msg.getDirectives();
    if (oldDirective.length == 1) {
      msg.setDirectives(new Directive[0]);
      //if(debug)
      //System.out.println("WARNING: removing last directive.");
      return true;
    }

    Directive[] newDirective = new Directive[oldDirective.length - 1];
    int i;

    for (i = 0; i < index; i++) {
      newDirective[i] = oldDirective[i];
    }
    for (i = index; i < newDirective.length; i++) {
      newDirective[i] = oldDirective[i + 1];
    }
    msg.setDirectives(newDirective);
    //if(debug)
    //System.out.println("WARNING: removed IN directive " + index);
    return false;
  }//removeDirective

  /* (non-Javadoc)
   * @see org.cougaar.core.security.access.message.AccessAgentProxy#checkMessage(org.cougaar.core.mts.Message, boolean)
   */
  /*  protected boolean checkMessage(Message msg, boolean direction) {
      if (log.isDebugEnabled()) {
      log.debug("checkMessage(" + msg + "), class " + msg.getClass().getName() + ", direction " + direction);
      }
      String source = msg.getOriginator().toString();
      String target = msg.getTarget().toString();
      if (msg instanceof DirectiveMessage) {
      return checkDirectiveMessage(source, target, msg, direction);
      }
    
      if (msg instanceof WPQuery) {
      // first still need to know whether source and target are allowed to talk
      if (!isMessageDenied(source, target, null, direction)) {
      return checkWPQueryMessage(target, (WPQuery)msg);
      }
      }
      return isMessageDenied(source, target, null, direction);
      }
  */
}
