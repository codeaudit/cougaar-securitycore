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
 * Created on September 12, 2001, 10:55 AM
 */

package com.nai.security.crypto;

import org.cougaar.core.component.*;
import org.cougaar.core.mts.*;

import org.cougaar.core.cluster.DirectiveMessage;
import org.cougaar.core.cluster.ClusterMessage;
import org.cougaar.core.society.Message;
import org.cougaar.core.society.MessageEnvelope;
import org.cougaar.core.society.MessageAddress;
import org.cougaar.core.society.NodeIdentificationService;
import com.nai.security.access.AccessControlPolicyService;
import com.nai.security.access.IntegrityAttribute;
import com.nai.security.access.MissionCriticality;
import com.nai.security.access.TrustSet;
import com.nai.security.access.TrustAttribute;
import org.cougaar.core.security.policy.AccessControlPolicy;

import org.cougaar.domain.planning.ldm.plan.Directive;
import org.cougaar.domain.planning.ldm.plan.Verb;
import org.cougaar.domain.planning.ldm.plan.Task;

//import java.io.Serializable;
import java.security.*;
//import java.security.cert.*;
import javax.crypto.*;
import java.util.*;
import java.security.cert.CertificateException;
import java.lang.RuntimeException;

/**
 *
 * The message is unsecured by a SecureDeliverer aspect delegate
 * and is secured by a SecureDestinationLink delegate.
 *
 * */

public class SecurityAspect extends StandardAspect
{
  private static CryptoManagerService cms = null;
  private static CryptoPolicyService cps = null;
  private static AccessControlPolicyService acps = null;

  private static String smlist[]={"CLEAR","SIGN","ENCRYPT","SIGN+ENCRYPT"};
  private static boolean enabled = false;
  private static boolean debug = false;
  private static int infoLevel = 0;

  /** Do we use the cryptographic service? */
  //  private static String nodeName= null;
  //private static Verb TRANSPORT = new Verb("Transport");
  private static String SECURE_PROPERTY =
    "org.cougaar.message.transport.secure";

  private boolean firsttime=true;
  private ServiceBroker sb=null;

  public SecurityAspect() {
    // Do not use this aspect anymore. It is not maintained
    System.err.println("WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    System.err.println("This security aspect is outdated and not maintained");
    System.err.println("Use CryptoAspect and AccessControlAspect instead");

    String db = System.getProperty("org.cougaar.message.transport.debug");
    if ( db!=null && (db.equalsIgnoreCase("true") || db.indexOf("security")>=0) ) debug=true;

    infoLevel = (Integer.valueOf(System.getProperty("org.cougaar.security.info","0"))).intValue();

    //add crypto related services:
    sb = new ServiceBrokerSupport();
    //    setChildServiceBroker(sb);
    CryptoManagerServiceProvider cmsp = new CryptoManagerServiceProvider();
    sb.addService(CryptoManagerService.class, cmsp);
    sb.addService(CryptoPolicyService.class, cmsp);
    sb.addService(AccessControlPolicyService.class, cmsp);

  }

  public static Message getInnerMessage(Message aMessage)
  {
    /* Currently supported messages are:
     * - AdvanceClockMessage
     * - AggregationPlugIn.XMLMessage
     * - ClusterMessage
     *    - AckDirectiveMessage
     *    - ClusterInitializedMessage
     *    - DirectiveMessage
     * - ComponentMessage
     * - FakeReplyMessage
     * - FakeRequestMessage
     * - MessageEnvelope
     *    - TrafficMaskingGeneratorAspect.MaskingMessageEnvelope
     * - MoveAgentMessage
     * - NodeMessage
     * - PolicyMulticastMessage
     */
    if (!(aMessage instanceof MessageEnvelope)) {
      // The message is not wrapped in an envelope. That's what we want.
      // Return it.
      return aMessage;
    }
    else {
      // The message is wrapped in an envelope.
      // Recursively unwrap it.
      return getInnerMessage(((MessageEnvelope)aMessage).getContents());
    }
  }

  private static class SecurityEnvelope extends MessageEnvelope {
    //for access control
    private TrustSet[] set = null;
    //for crypto
    private SignedObject signedMsg = null;
    private SealedObject sealedMsg = null;
    private SealedObject secret = null;    // The encrypted session key
    private Message msg = null;

    SecurityEnvelope(Message m, TrustSet[] ts)
      throws RuntimeException, CertificateException,
	     java.security.NoSuchAlgorithmException, java.security.InvalidKeyException,
	     java.io.IOException, javax.crypto.NoSuchPaddingException,
	     javax.crypto.IllegalBlockSizeException {

      //we don't want m to be the contend, so just make a null one.
      super(null, m.getOriginator(), m.getTarget());
      //SET UP TRUST ATTRIBUTES
      set = new TrustSet[ts.length];
      for(int i=0; i<ts.length; i++){
	set[i]=ts[i];
      }

      //NOW ENCRYPT
      String Origin = m.getOriginator().getAddress();
      String Target = m.getTarget().getAddress();
      String keyName;
      SecureMethodParam s = cps.getSendPolicy(Origin+":"+Target);
      if(s==null) throw new RuntimeException("no policy available for securing the message:"+m);

      if(debug) System.out.println("securing message with method "+smlist[s.secureMethod]+":"+Origin+"--"+Target);

      if(s.secureMethod==s.PLAIN){
	msg = m;
	return;
      }else if(s.secureMethod==s.SIGN){
	keyName = Origin;
	signedMsg = cms.sign(keyName,s.signSpec,m);
      }else if(s.secureMethod==s.ENCRYPT){
	/*generate the secret key*/
	int i=s.symmSpec.indexOf("/");
	String a;

	a =  i > 0 ? s.symmSpec.substring(0,i) : s.symmSpec;
	SecureRandom random = new SecureRandom();
	KeyGenerator kg=KeyGenerator.getInstance(a);
	kg.init(random);
	SecretKey sk=kg.generateKey();
	keyName = Target;
	secret=cms.asymmEncrypt(keyName,s.asymmSpec,sk);
	sealedMsg = cms.symmEncrypt(sk,s.symmSpec,m);

      }else if(s.secureMethod==s.SIGNENCRYPT){
	/*generate the secret key*/
	int i=s.symmSpec.indexOf("/");
	String a;
	a =  i > 0 ? s.symmSpec.substring(0,i) : s.symmSpec;
	if(debug) {
	  System.out.println("Secret Key Parameters: " + a);
	}
	SecureRandom random = new SecureRandom();
	KeyGenerator kg=KeyGenerator.getInstance(a);
	kg.init(random);
	SecretKey sk=kg.generateKey();
	keyName = Target;

	// Encrypt session key
	secret=cms.asymmEncrypt(keyName,s.asymmSpec,sk);

	// Encrypt message itself
	sealedMsg = cms.symmEncrypt(sk,s.symmSpec,m);

	keyName = Origin;
	// Sign message
	signedMsg = cms.sign(keyName,s.signSpec,sealedMsg);
      }else {
	throw new RuntimeException("SecurityAspect: incorrect secureMethod parameter.");
      }
    }
    /*
        protected TrustSet[] getTrustSets(){
            return set;
        }
*/

    public Message getContents() {
      try{
	//unsecure the message
	Message m = unsecure();
	//check tags
	if (m == null) return null;
	//TrustSet[] ts = getTrustSets();
	if (set == null) return m;
	Message innerMessage = getInnerMessage(m);
	checkInVerbs(innerMessage);
	incomingTrust(innerMessage, set);
	if(!incomingMessageAction(innerMessage, set[0])) return null;
	if(!incomingAgentAction(innerMessage)) return null;
	return m;
      }catch(Exception e){
	e.printStackTrace();
	return null;
      }
    }

    //check if the secure method being used matches
    //the content of message
    private boolean policyMatch(int method)
    {
      if(method==SecureMethodParam.PLAIN){
	if(msg != null) {
	  return true;
	}
      }else if(method==SecureMethodParam.ENCRYPT){
	if(secret!=null && sealedMsg!=null) {
	  return true;
	}
      }else if(method==SecureMethodParam.SIGN){
	if(signedMsg != null) {
	  return true;
	}
      }else if(method==SecureMethodParam.SIGNENCRYPT){
	if(signedMsg!=null && secret!=null && sealedMsg!=null) {
	  return true;
	}
      }

      return false;
    }

    private Message unsecure()
      throws RuntimeException, CertificateException {
      String Origin = getOriginator().getAddress();
      String Target = getTarget().getAddress();
      SecureMethodParam param = null;
      param = cps.getReceivePolicy(Origin+":"+Target);
      if(!policyMatch(param.secureMethod)){
	//try boot policy
	if(debug) System.out.println("unmatching unsecuring method "+smlist[param.secureMethod]+":"+Origin+"--"+Target);
	param = cps.getReceivePolicy("BOOT"+":"+"DEFAULT");
	if(!policyMatch(param.secureMethod)){
	  if(debug) System.out.println("couldn't match unsecuring method "+smlist[param.secureMethod]+" for :"+Origin+"--"+Target);
	  //boot didn't match, quit.
	  return null;
	}
      }

      if(param==null) throw new RuntimeException("no policy available for un-securing the message:"+this);
      String keyName;

      if(debug) System.out.println("unsecuring message with method "+smlist[param.secureMethod]+":"+Origin+"--"+Target);
      if(param.secureMethod==SecureMethodParam.PLAIN){
	return msg;
      }else if(param.secureMethod==SecureMethodParam.ENCRYPT){
	keyName = Target;
	SecretKey sk = (SecretKey)
	  cms.asymmDecrypt(keyName, param.asymmSpec, secret);
	if (sk == null) {
	  if (debug) {
	    System.out.println("Error: unable to retrieve secret key");
	  }
	  return null;
	}
	return (Message)cms.symmDecrypt(sk,sealedMsg);
      }else if(param.secureMethod==SecureMethodParam.SIGN){
	keyName = Origin;
	return (Message)cms.verify(keyName, param.signSpec, signedMsg);
      }else if(param.secureMethod==SecureMethodParam.SIGNENCRYPT){
	keyName = Origin;
	// Verify the signature
	SealedObject so=(SealedObject)cms.verify(keyName, param.signSpec, signedMsg);
	if (so==null) return null;    //should we do something more???
	keyName = Target;
	// Retrieving the secret key, which was encrypted using the public key
	// of the target.
	SecretKey sk=(SecretKey)cms.asymmDecrypt(keyName, param.asymmSpec, secret);
	return (Message)cms.symmDecrypt(sk, so);
      }
      return null;
    }

    private void compare(TrustSet msgSet, TrustSet policySet) {
      if(policySet == null || msgSet == null)return;
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

    private void checkInVerbs(Message msg) {
      if (debug) {
	System.out.println("Incoming message:" + msg.getClass().toString());
      }
      if(msg instanceof DirectiveMessage) {
        Directive directive[] =
          ((DirectiveMessage)msg).getDirectives();
	int len = directive.length;
        for(int i = 0; i < len; i++) {
	  if (debug) {
	    System.out.println("IN Directive[" + i + "]:"
			       + directive[i].getClass().toString());
	  }
          if(!(directive[i] instanceof Task))
            continue;
          Task task = (Task)directive[i];
          if(debug) {
	    System.out.println("SecurityAspect: processing IN task w/Verb: "
			       + task.getVerb() + " of " + len);
	  }
          if(!matchInVerb(task.getDestination().toString(),
                         task.getSource().toString(),
                         task.getVerb())) {
            if(removeDirective((DirectiveMessage)msg, i)) return;
	    directive = ((DirectiveMessage)msg).getDirectives();
	    len = directive.length;
	    i--;
          }
        }
      }
    }

    private boolean matchInVerb(String target, String source, Verb verb) {
      Object[] verbs = acps.getIncomingVerbs(target, source);
      if( verbs[0].toString()=="*" ) {
	  if(debug) System.out.println("SecurityAspect: got IN * verb, so passing "+verb+" for " + target);
        return true;
      }

      if(verb == null || verbs.length == 0) {
	if(debug) {
	  System.out.println("SecurityAspect: no incoming verbs for"
			     + target + ", " + source + ", blocking: "
			     + verb);
	}
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
	if (debug) {
	  System.out.println("Got verb:" + v);
	}

	if(verb.equals(v)) {
	  if(debug)System.out.println("SecurityAspect: matched in verbs, passing: "
				      + verbs[i] + " == " + verb);
	  return true;	// we found a match so return success
	}
      }
      if(debug)System.out.println("SecurityAspect: not matched, so blocking: "+verb);
      return false;		// we found no matches so return false
    }

    private void incomingTrust(Message msg, TrustSet[] set) {
      TrustSet policySet;
      try {
	policySet = acps.getIncomingTrust
	  (msg.getTarget().toString(),
	   msg.getOriginator().toString());
      }
      catch(Exception ex) {
	System.out.println("Warning: no msg incoming trust for type = "
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
	    (directive[i].getDestination().toString(),
	     directive[i].getSource().toString());
	  if(set[i+1] == null){
	    set[i+1] = policy; //new TrustSet();
	  }else{
	    if(directive[i] instanceof Task) {
	      Task task = (Task)directive[i];
//	      if(matchInVerb(task.getDestination().toString(),
//			     task.getSource().toString(),
//			     task.getVerb())) {
		set[i+1] = policy;
//	      } else {
//		compare(set[i+1], policy);
//	      }
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
	  (msg.getTarget().toString(), msg.getOriginator().toString());
      }
      catch(Exception ex) {
	System.out.println("Warning: no access control for message type " + msg.getClass());
	return true;
      }
      if(debug)System.out.println("SecurityAspect: action(in) = " + action);
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
	if(debug)System.out.println("SecurityAscpect: processing in task "
				    + i);

	Task task = (Task)directive[i];
//	if(matchInVerb(task.getDestination().toString(),
//		       task.getSource().toString(),
//		       task.getVerb()))
	  action = acps.getIncomingAgentAction
	    (task.getDestination().toString(),
	     task.getSource().toString());
	if(action == null)
	  continue;
	if(action.equals(AccessControlPolicy.SET_ASIDE)){
	  if(removeDirective(msg, i)) return false;
	  directive = ((DirectiveMessage)msg).getDirectives();
	  len = directive.length;
	  i=i--;
	}
      }
      //return (msg.getDirectives().length > 0);
      return true;
    }

    private boolean incomingMessageAction(Message msg, TrustSet t) {
      //if(!(msg instanceof DirectiveMessage))
      //return true;
      String action;
      try {
	action = acps.getIncomingAction
	  (msg.getTarget().toString(), (String)t.getAttribute(MissionCriticality.name).getValue());
      }
      catch(Exception ex) {
	System.out.println("Warning: no access control for message" + msg);
	return true;
      }
      if(debug)System.out.println("SecurityAspect: message action(in) = " + action);
      if(action == null)
	return true;
      return (!action.equals(AccessControlPolicy.SET_ASIDE));
    }
  }
    /** removes the nth directive from a directive message */
    private static boolean removeDirective(DirectiveMessage msg, int index) {
      Directive[] oldDirective = msg.getDirectives();
      //if(oldDirective.length == 0) return;
      if(oldDirective.length == 1){
	  msg.setDirectives(new Directive[0]);
	  if(debug)System.out.println("removing last directive.");
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
      if(debug)System.out.println("SecurityAspect: removed IN directive " +
				  index);
      return false;
    }//removeDirective

  private void init(){
    enabled = true;
    //    sb = getServiceBroker();
    if (sb != null){
      try{
	cms = (CryptoManagerService)sb.getService(this, CryptoManagerService.class, null);
	cps = (CryptoPolicyService)sb.getService(this, CryptoPolicyService.class, null);
	acps = (AccessControlPolicyService)sb.getService(this, AccessControlPolicyService.class, null);
      }
      catch(Exception e){
	throw new RuntimeException("failed to initialize security Aspect:"+e.toString());
      }
    }else{
      throw new RuntimeException("No service broker when trying to initialize SecurityAspect.");
    }
  }

  public Object getDelegate(Object delegate, Class type)
  {
    //make sure we are initialized
    if(!enabled) init();
    if (type ==  DestinationLink.class) {
      DestinationLink link = (DestinationLink) delegate;
      //	    if (link.getProtocolClass() == LoopbackLinkProtocol.class)
      //		return null;
      //	    else
      return new SecureDestinationLink(link);
    } else {
      return null;
    }
  }

  public Object getReverseDelegate(Object delegate, Class type)
  {
    //make sure we are initialized
    if(!enabled) init();
    if (type == MessageDeliverer.class) {
      return new SecureDeliverer((MessageDeliverer) delegate);
    } else {
      return null;
    }
  }

  private class SecureDestinationLink
    extends DestinationLinkDelegateImplBase
  {
    private SecureDestinationLink(DestinationLink link) {
      super(link);
    }

    public void forwardMessage(Message message)
      throws UnregisteredNameException,
	     NameLookupException,
	     CommFailureException,
	     MisdeliveredMessageException
    {
      try {
	TrustSet[] ts;
	Message innerMessage = getInnerMessage(message);
	ts = checkOutgoing(innerMessage);
	checkOutVerbs(innerMessage);

	if(ts==null) {
	  if(debug) {
	    System.out.println("Rejecting outgoing message: " +
			       ((message != null)? message.toString():
				"Null Message"));
	  }
	  return;		// the message is rejected so we abort here
	}
	SecurityEnvelope se;
	//mSecured = (secure)? secure(message): message;
        se = new SecurityEnvelope(message, ts);
	if (se != null) {
	  link.forwardMessage(se);
	}
	else {
	  if (debug) {
	    System.out.println("Security Aspect. Message " + message + " cannot be sent");
	  }
	}
      } catch (CertificateException e) {
	if (infoLevel > 0) {
	  System.out.println("Unable to secure message: " + message );
	}
	if (debug) {
	  System.out.println(". Reason: " + e.getMessage());
	  e.printStackTrace();
	}
      } catch (NoSuchAlgorithmException e) {
      } catch (InvalidKeyException e) {
      } catch (java.io.IOException e) {
      } catch (NoSuchPaddingException e) {
      } catch (IllegalBlockSizeException e) {
      }
      // Do not catch non-security related exceptions.
    }

    private TrustSet[] checkOutgoing(Message msg) {
      if(msg == null)return null;
      TrustSet[] trust;
      trust = outgoingTrust(msg);
      if(!outgoingMessageAction(msg, trust[0])) return null;
      if(!outgoingAgentAction(msg)) return null;
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
	System.out.println("Warning: no msg outgoing trust for type = "
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
//	      if(matchOutVerb(task.getDestination().toString(),
//			      task.getSource().toString(),
//			      task.getVerb())) {
		set[i+1] = policy;
//	      } else {
//		compare(set[i+1], policy);
//	      }
	    } else
	      compare(set[i+1], policy);
	  }
	}
      }
      return set;
    }

    private void checkOutVerbs(Message msg) {
      if (debug) {
	System.out.println("Outgoing message:" + msg.getClass().toString());
      }

      if(msg instanceof DirectiveMessage) {
        Directive directive[] =
          ((DirectiveMessage)msg).getDirectives();
	int len = directive.length;
        for(int i = 0; i < len; i++) {
	  if (debug) {
	    System.out.println("OUT Directive[" + i + "]:"
			       + directive[i].getClass().toString());
	  }
	  if(!(directive[i] instanceof Task))
            continue;

          if(debug)System.out.println("SecurityAspect: processing OUT task "
                                      + i);
          Task task = (Task)directive[i];
          if(!matchOutVerb(task.getDestination().toString(),
                         task.getSource().toString(),
                         task.getVerb())) {
            if(removeDirective((DirectiveMessage)msg, i)) return;
	    directive = ((DirectiveMessage)msg).getDirectives();
	    len = directive.length;
	    i--;
          }
        }
      }
    }


    private boolean matchOutVerb(String source, String target, Verb verb) {
      Object[] verbs = acps.getOutgoingVerbs(source, target);
      if( verbs[0].toString()=="*" ) {
	  //if(debug) System.out.println("SecurityAspect: got OUT * verb, so blocking "+verb+" for " + source);
        return true;
      }

      if(verb == null || verbs.length == 0) {
        if(debug)System.out.println("SecurityAspect: no out verbs for "
				    + source + ", " + target + ", " + verb );
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
	  if(debug)System.out.println("SecurityAspect: matched out verbs "
				      + verbs[i] + " == " + verb);
	  return true;	// we found a match so return success
	}
      }
      return false;		// we found no matches so return false
    }

    private boolean outgoingAgentAction(Message msg) {
      String action;
      try {
	action = acps.getOutgoingAgentAction
	  (msg.getOriginator().toString(), msg.getTarget().toString());
      }
      catch(Exception ex) {
	System.out.println("Warning: no access control for message type " + msg.getClass());
	return true;
      }
      if(debug)System.out.println("SecurityAspect: action(out) = " + action);
      if(action == null)
	return true;
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
//	if (matchOutVerb(task.getSource().toString(),
//			 task.getDestination().toString(),
//			 task.getVerb()))
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
      if(debug)System.out.println("SecurityAspect: DirectiveMessage now contains " +
				  msg.getDirectives().length +
				  " directives.");
      //return (msg.getDirectives().length > 0);
      return true;
    }

    private boolean outgoingMessageAction(Message msg, TrustSet trust) {
      // if(!(msg instanceof DirectiveMessage))
      //return true;
      String act;
      try {
	act = acps.getOutgoingAction
	  (msg.getOriginator().toString(),
	   (String)trust.getAttribute(MissionCriticality.name).getValue());
      }
      catch(Exception ex) {
	ex.printStackTrace();
	System.out.println("SecurityAspect: Warning: no access control for message" + msg);
	return true;
      }
      if(debug) {
	System.out.println("SecurityAspect: message action(out) = " +
			   (act == null ? "No policy (pass through)" : act));
      }

      if(act == null)
	return true;
      return (!act.equals(AccessControlPolicy.SET_ASIDE));
    }
  }

  private class SecureDeliverer extends MessageDelivererDelegateImplBase {
    private SecureDeliverer(MessageDeliverer deliverer) {
      super(deliverer);
    }

    public void deliverMessage(Message m, MessageAddress dest)
      throws MisdeliveredMessageException
    {
      try {
        if (m instanceof SecurityEnvelope ) {
	  SecurityEnvelope se = (SecurityEnvelope)m;
	  if (se == null) {
	    if(debug) {
	      System.out.println("Unable to deliver message (msg is null) to " + dest);
	    }
	    throw new MisdeliveredMessageException(m);
	  }
	  Message contents = se.getContents();
	  if(contents == null) {
	    if(debug) {
	      System.out.println("Rejecting incoming message: "
				 + se.toString());
	    }
	    return;
	  }else{
	    //System.out.println("________delivering this:"+contents+" to:"+dest+"using:"+deliverer);
	    deliverer.deliverMessage(contents, dest);
	  }
        } else {
	  System.err.println("Warning: Not a SecurityEnvelope: " + m);
	  deliverer.deliverMessage(m, dest);
        }
      } catch (Exception e) {
	System.out.println("Unable to unsecure message: " + m + ". Reason: " + e.getMessage());
        e.printStackTrace();
      }
    }
  }
}

