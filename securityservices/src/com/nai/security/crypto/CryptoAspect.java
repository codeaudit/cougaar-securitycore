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

import java.security.*;
import javax.crypto.*;
import java.util.*;
import java.security.cert.CertificateException;
import java.lang.RuntimeException;

import org.cougaar.core.component.*;
import org.cougaar.core.mts.*;

import org.cougaar.core.blackboard.DirectiveMessage;
import org.cougaar.core.agent.ClusterMessage;
import org.cougaar.core.node.NodeIdentificationService;

import com.nai.security.access.AccessControlPolicyService;
import com.nai.security.access.IntegrityAttribute;
import com.nai.security.access.MissionCriticality;
import com.nai.security.access.TrustSet;
import com.nai.security.access.TrustAttribute;

import org.cougaar.core.security.policy.AccessControlPolicy;
import org.cougaar.planning.ldm.plan.Directive;
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.planning.ldm.plan.Task;

import com.nai.security.util.SecurityPropertiesService;
import org.cougaar.core.security.crypto.CryptoServiceProvider;
import org.cougaar.core.security.services.crypto.EncryptionService;

/**
 *
 * The message is unsecured by a SecureDeliverer aspect delegate 
 * and is secured by a SecureDestinationLink delegate.
 *
 * */
public class CryptoAspect extends StandardAspect
{
  private static EncryptionService cms = null; 
  private static CryptoPolicyService cps = null;

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

  private SecurityPropertiesService secprop = null;
  
  public CryptoAspect() {
    // TODO. Modify following line to use service broker instead
    secprop = CryptoServiceProvider.getSecurityProperties();

    String db = secprop.getProperty(secprop.TRANSPORT_DEBUG);
    if ( db!=null && (db.equalsIgnoreCase("true") ||
		      db.indexOf("security")>=0) ) debug=true;
    infoLevel = (Integer.valueOf(secprop.getProperty(secprop.SECURITY_DEBUG,
						     "0"))).intValue();

    //add crypto related services:
    sb = new ServiceBrokerSupport();
    //    setChildServiceBroker(sb);
    CryptoManagerServiceProvider cmsp = new CryptoManagerServiceProvider();
    sb.addService(EncryptionService.class, cmsp);
    sb.addService(CryptoPolicyService.class, cmsp);                
  }

  private void init(){
    enabled = true;
    //    sb = getServiceBroker();
    if (sb != null){
      try{
	cms = (EncryptionService)
	  sb.getService(this, EncryptionService.class, null);
	cps = (CryptoPolicyService)
	  sb.getService(this, CryptoPolicyService.class, null);
      }
      catch(Exception e){
	throw new RuntimeException("failed to initialize security Aspect:"
				   +e.toString());
      }
    } else {
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

  /** ***************************************************
   *  CryptoSecurityEnvelope
   */
  private static class CryptoSecurityEnvelope extends MessageEnvelope {
    //for crypto
    private SignedObject signedMsg = null;
    private SealedObject sealedMsg = null;
    private SealedObject secret = null;    // The encrypted session key
    private Message msg = null;
        
    CryptoSecurityEnvelope(Message m) 
      throws RuntimeException, CertificateException,
	     java.security.NoSuchAlgorithmException,
	     java.security.InvalidKeyException,
	     java.io.IOException, javax.crypto.NoSuchPaddingException,
	     javax.crypto.IllegalBlockSizeException {
      //we don't want m to be the contend, so just make a null one.
      super(null, m.getOriginator(), m.getTarget());
                 
      //NOW ENCRYPT
      String Origin = m.getOriginator().getAddress();
      String Target = m.getTarget().getAddress();
      String keyName;
      SecureMethodParam s = cps.getSendPolicy(Origin+":"+Target);
      if(s==null) {
	throw new
	  RuntimeException("No policy available for securing the message:"+m);
      }
      if(debug) {
	System.out.println("securing message with method "
			   +smlist[s.secureMethod]+":"
			   + Origin + "--" + Target);
      }
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

    public Message getContents() {
      try{
	//unsecure the message
	Message m = unsecure();
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
	if(debug) System.out.println("unmatching unsecuring method "
				     +smlist[param.secureMethod]+":"+Origin+"--"+Target);
	param = cps.getReceivePolicy("BOOT"+":"+"DEFAULT");
	if(!policyMatch(param.secureMethod)){
	  if(debug) {
	    System.out.println("couldn't match unsecuring method "
			       +smlist[param.secureMethod]+" for :"+Origin+"--"+Target);
	  }
	  //boot didn't match, quit.
	  return null;
	}
      }

      if(param==null) throw new RuntimeException("no policy available for un-securing the message:"+this);
      String keyName;

      if(debug) System.out.println("unsecuring message with method "
				   +smlist[param.secureMethod]
				   +":"+Origin+"--"+Target);
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
	SealedObject so=(SealedObject)
	  cms.verify(keyName, param.signSpec, signedMsg);
	if (so==null) return null;    //should we do something more???
	keyName = Target;

	// Retrieving the secret key, which was encrypted using the public key
	// of the target.
	SecretKey sk=(SecretKey)
	  cms.asymmDecrypt(keyName, param.asymmSpec, secret);
	if (sk == null) {
	  if (debug) {
	    System.out.println("Error: unable to retrieve secret key");
	  }
	  return null;
	}
	return (Message)cms.symmDecrypt(sk, so);
      }
      return null;
    }
  }
    
  /** ***************************************************
   *  SecureDestinationLink
   */
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
	CryptoSecurityEnvelope se;
        se = new CryptoSecurityEnvelope(message);
	if (se != null) {
	  link.forwardMessage(se);
	}
	else {
	  if (debug) {
	    System.out.println("Security Aspect. Message "
			       + message + " cannot be sent");
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
      // It is up to the caller to figure out what to do.
    }
  }


  /** ***************************************************
   *  SecurityDeliver
   */

  private class SecureDeliverer extends MessageDelivererDelegateImplBase {

    private SecureDeliverer(MessageDeliverer deliverer) {
      super(deliverer);
    }

    public void deliverMessage(Message m, MessageAddress dest) 
      throws MisdeliveredMessageException
    {
      if (m instanceof CryptoSecurityEnvelope ) {
	CryptoSecurityEnvelope se = (CryptoSecurityEnvelope)m;
	if (se == null) {
	  if(debug) {
	    System.out.println("Unable to deliver message (msg is null) to "
			       + dest);
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
	  deliverer.deliverMessage(contents, dest);
	}
      } else {
	/* Incoming messages should always be wrapped in a
	 * SecurityEnvelope. This allows the cryptographic service
	 * to verify that the incoming message satisfies the
	 * cryptographic policy.
	 * If an incoming message is not wrapped in a security
	 * envelope, then we discard the message.
	 */
	if (debug) {
	  System.err.println("Error: Not a CryptoSecurityEnvelope: " + m);
	}
	return;
	//deliverer.deliverMessage(m, dest);
      }
    }
  }
}
