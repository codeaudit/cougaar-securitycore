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

package org.cougaar.core.security.crypto;

import java.io.Serializable;
import java.io.IOException;
import java.security.*;
import java.util.*;
import java.security.cert.*;
import javax.crypto.*;

// Cougaar core infrastructure
import org.cougaar.core.component.ServiceRevokedListener;
import org.cougaar.core.component.ServiceRevokedEvent;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;

// Cougaar Security Services
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.crypto.PublicKeyEnvelope;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.monitoring.event.MessageFailureEvent;
import org.cougaar.core.security.policy.CryptoPolicy;

public class CryptoManagerServiceImpl
  implements EncryptionService
{
  private KeyRingService keyRing;
  private ServiceBroker serviceBroker;
  private LoggingService log;
  private HashMap        ciphers = new HashMap();

  /** A hashtable that contains encrypted session keys.
   *  The session keys may be used for multiple messages instead of having to generate and encrypt
   *  the secret key every time a message is sent.
   *  The hashtable key is an MessageAddressPair
   *  The hashtable value is a SealedObject (the encrypted session key)
   */
  private Hashtable sessionKeys;


  public CryptoManagerServiceImpl(KeyRingService aKeyRing, ServiceBroker sb) {
    keyRing = aKeyRing;
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    sessionKeys = new Hashtable();
  }

  public SignedObject sign(final String name,
			   String spec,
			   Serializable obj)
    throws GeneralSecurityException, IOException {
    List pkList = (List)
    AccessController.doPrivileged(new PrivilegedAction() {
	    public Object run(){
	      return keyRing.findPrivateKey(name);
	    }
	  });
    if (pkList == null || pkList.size() == 0) {
      String message = "Unable to sign object. Private key of " + name
	      + " does not exist.";
      if (log.isWarnEnabled()) {
	      log.warn(message);
      }

      throw new CertificateException("Private key not found.");
    }
    PrivateKey pk = ((PrivateKeyCert)pkList.get(0)).getPrivateKey();
    Signature se;
    // if(spec==null||spec=="")spec=pk.getAlgorithm();

    // Richard Liao
    // private key might not be found, if pending is required
    // the certficates are not approved automatically.
    // when agent is started with signAndEncrypt without
    // obtaining a certificate successfully this will generate
    // null pointer exception

    spec = AlgorithmParam.getSigningAlgorithm(pk.getAlgorithm());
    se=Signature.getInstance(spec);
    return new SignedObject(obj, pk, se);
  }

  public Cipher getCipher(String spec)
    throws NoSuchAlgorithmException, NoSuchPaddingException {
    ArrayList list;
    synchronized (this.ciphers) {
      list = (ArrayList) this.ciphers.get(spec);
      if (list == null) {
        list = new ArrayList();
        this.ciphers.put(spec,list);
      }
    }

    synchronized (list) {
      if (!list.isEmpty()) {
        return (Cipher) list.remove(list.size() - 1);
      }
    }
    return Cipher.getInstance(spec);
  }

  public void returnCipher(String spec, Cipher cipher) {
    ArrayList list;
    synchronized (this.ciphers) {
      list = (ArrayList) this.ciphers.get(spec);
    }
    synchronized (list) {
      list.add(cipher);
    }
  }

  public Object verify(String name, String spec, SignedObject obj)
    throws CertificateException {
    return verify(name, spec, obj, false);
  }

  public Object verify(String name, String spec, SignedObject obj, boolean expiredOk)
    throws CertificateException {
    List certList =
      keyRing.findCert(name,
		       KeyRingService.LOOKUP_LDAP |
		       KeyRingService.LOOKUP_KEYSTORE, !expiredOk);
    if (certList == null || certList.size() == 0) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to verify object. Certificate of " + name
		 + " does not exist.");
      }
      throw
	new CertificateException("Verify. Unable to get certificate for "
				 + name);
    }
    Iterator it = certList.iterator();

    while (it.hasNext()) {
      try {
        CertificateStatus cs = (CertificateStatus)it.next();
	java.security.cert.Certificate c = cs.getCertificate();
    // filter out those non valid certificates first
        if (expiredOk) {
          try {
            keyRing.checkCertificateTrust((X509Certificate)c);
          } catch (CertificateException ce) {
            if (!(ce instanceof CertificateExpiredException))
              continue;
            if (log.isDebugEnabled())
              log.debug("Certificate has expired." + cs.getCertificateAlias());
          }
        }

	PublicKey pk = c.getPublicKey();
	Signature ve;
	//if(spec==null||spec=="")spec=pk.getAlgorithm();
	spec = AlgorithmParam.getSigningAlgorithm(pk.getAlgorithm());
	ve=Signature.getInstance(spec);
	if (obj.verify(pk,ve)) {
	  return obj.getObject();
	} else {
	  // That's OK. Maybe there is an old certificate which is not
	  // trusted anymore, but we may have a newer one too.
	  continue;
	}
      } catch (Exception e) {
	// That's OK. Maybe there is an old certificate which is not
	// trusted anymore, but we may have a newer one too.
	if (log.isInfoEnabled()) {
	  log.info("Unable to verify signature", e);
	}
	continue;
      }
    }
    // No suitable certificate was found.
    if (log.isWarnEnabled()) {
      log.warn("Signature verification failed. Agent=" + name
	+ " - Tried with " + certList.size() + " certificates");
    }
    return null;
  }

  public SealedObject asymmEncrypt(String name, String spec, Serializable obj,
				   java.security.cert.Certificate cert)
    throws GeneralSecurityException, IOException {
    /*encrypt the secretekey with receiver's public key*/

    PublicKey key = cert.getPublicKey();

    if (spec==""||spec==null) {
      spec=key.getAlgorithm();
    }
    if (log.isDebugEnabled()) {
      log.debug("Encrypting for " + name + " using " + spec);
    }
    /*init the cipher*/
    Cipher ci = getCipher(spec);
    ci.init(Cipher.ENCRYPT_MODE,key);
    SealedObject so = new SealedObject(obj,ci);
    returnCipher(spec,ci);
    return so;
  }

  public Object asymmDecrypt(final String name,
			     String spec,
			     SealedObject obj){
    /*get secretKey*/
    List keyList = (List)
      AccessController.doPrivileged(new PrivilegedAction() {
	  public Object run(){
	    return keyRing.findPrivateKey(name);
	  }
	});
    if (keyList == null || keyList.size() == 0) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to decrypt object with public key. Private key of " + name
	  + " was not found.");
      }
      return null;
    }
    Iterator it = keyList.iterator();
    PrivateKey key = null;
    Cipher ci = null;
    while (it.hasNext()) {
      key = ((PrivateKeyCert)it.next()).getPrivateKey();
      if(spec==null||spec=="")
	spec=key.getAlgorithm();
      try {
	ci=getCipher(spec);
        ci.init(Cipher.DECRYPT_MODE, key);
        Object o = obj.getObject(ci);
        returnCipher(spec,ci);
        return o;
      }
      catch (Exception e) {
	// That's OK. Maybe there is an old certificate which is not
	// trusted anymore, but we may have a newer one too.
	if (log.isInfoEnabled()) {
	  log.info("Cannot recover message. " + e
	    + ". Trying with next certificate...");
	}
	continue;
      }
    }
    if (log.isWarnEnabled()) {
      log.warn("Cannot recover message. ");
    }
    return null;
  }

  public SealedObject symmEncrypt(SecretKey sk,
				  String spec,
				  Serializable obj)
  throws GeneralSecurityException, IOException {
    /*create the cipher and init it with the secret key*/
    Cipher ci;
    ci=getCipher(spec);
    ci.init(Cipher.ENCRYPT_MODE,sk);
    SealedObject so = new SealedObject(obj,ci);
    returnCipher(spec,ci);
    return so;
  }

  public Object symmDecrypt(SecretKey sk, SealedObject obj){
    Object o = null;
    if (sk == null) {
      if (log.isErrorEnabled()) {
	      log.error("Secret key not provided!");
      }
      return o;
    }

    String alg = obj.getAlgorithm();
    try{
      Cipher ci = getCipher(alg);
      ci.init(Cipher.DECRYPT_MODE, sk);
      o = obj.getObject(ci);
      returnCipher(alg,ci);
      return o;
    }
    catch(NullPointerException nullexp){
      boolean loop = true;
      if (log.isDebugEnabled()) {
	      log.debug("in symmDecrypt" +nullexp);
      }
      while(loop){
      	try{
      	  Thread.sleep(200);
          Cipher ci = getCipher(alg);
          ci.init(Cipher.DECRYPT_MODE, sk);
          o = obj.getObject(ci);
          returnCipher(alg,ci);
      	  if (log.isWarnEnabled()) {
      	    log.warn("Workaround to Cougaar core bug. Succeeded");
      	  }
      	  return o;
      	}
      	catch(NullPointerException null1exp){
      	  if (log.isWarnEnabled()) {
      	    log.warn("Workaround to Cougaar core bug (Context not known). Sleeping 200ms then retrying...");
      	  }
      	  continue;
      	}
      	catch(Exception exp1){
      	  log.info("Unable to decrypt object", exp1);
      	  continue;
      	}
      }
      return null;
    }
    catch(Exception e){
      if (log.isErrorEnabled()) {
	      log.error("Unable to decrypt object", e);
      }
      return null;
    }
  }

  public ProtectedObject protectObject(Serializable object,
				       MessageAddress source,
				       MessageAddress target,
				       SecureMethodParam policy)
  throws GeneralSecurityException, IOException {
    ProtectedObject po = null;

    if (object == null) {
      throw new IllegalArgumentException("Object to protect is null");
    }
    if (source == null) {
      throw new IllegalArgumentException("Source not specified");
    }
    if (target == null) {
      throw new IllegalArgumentException("Target not specified");
    }
    if (policy == null) {
      throw new IllegalArgumentException("Policy not specified");
    }

    int method = policy.secureMethod;
    if (log.isDebugEnabled()) {
      log.debug("Protect object " + source.toAddress() + " -> "
		+ target.toAddress() + " with policy: "
		+ method);
    }
    try {
      switch(method) {
      case SecureMethodParam.PLAIN:
      	po = new ProtectedObject(policy, object);
      	break;
      case SecureMethodParam.SIGN:
      	po = sign(object, source, target, policy);
      	break;
      case SecureMethodParam.ENCRYPT:
      	po = encrypt(object, source, target, policy);
      	break;
      case SecureMethodParam.SIGNENCRYPT:
      	po = signAndEncrypt(object, source, target, policy);
      	break;
      default:
	      throw new GeneralSecurityException("Invalid policy");
      }
    }
    catch (GeneralSecurityException gse) {
      if (log.isWarnEnabled()) {
	      log.warn("Unable to protect object: " + source.toAddress()
		      + " -> " + target.toAddress() + " - policy=" + method);
      }
      throw gse;
    }
    catch (IOException e) {
      if (log.isWarnEnabled()) {
	      log.warn("Unable to protect object: " + source.toAddress()
		    + " -> " + target.toAddress() + " - policy=" + method);
      }
      throw e;
    }
    return po;
  }

  public Object unprotectObject(MessageAddress source,
				MessageAddress target,
				ProtectedObject protectedObject,
				SecureMethodParam policy)
  throws GeneralSecurityException {
    Object theObject = null;
    if (protectedObject == null) {
      throw new IllegalArgumentException("Object to unprotect is null");
    }
    if (source == null) {
      throw new IllegalArgumentException("Source not specified");
    }
    if (target == null) {
      throw new IllegalArgumentException("Target not specified");
    }
    if (policy == null) {
      throw new IllegalArgumentException("Policy not specified");
    }

    // Check the policy.
    if (policy.secureMethod != protectedObject.getSecureMethod().secureMethod) {
      // The object does not comply with the policy
      GeneralSecurityException gse =
        new GeneralSecurityException("Object does not comply with the policy");
      throw gse;
    }

    // Unprotect the message.
    int method = policy.secureMethod;
    if (log.isDebugEnabled()) {
      log.debug("Unprotect object " + source.toAddress() + " -> "
		+ target.toAddress() + "with policy: "
		+ method);
    }
    try {
      switch(method) {
      case SecureMethodParam.PLAIN:
      	theObject = protectedObject.getObject();
      	break;
      case SecureMethodParam.SIGN:
      	theObject = verify(source, target,
      			   (PublicKeyEnvelope)protectedObject,
      			   policy);
      	break;
      case SecureMethodParam.ENCRYPT:
      	theObject = decrypt(source, target,
      			    (PublicKeyEnvelope)protectedObject,
      			    policy);
      	break;
      case SecureMethodParam.SIGNENCRYPT:
      	theObject = decryptAndVerify(source, target,
      				     (PublicKeyEnvelope)protectedObject,
      				     policy);
      	break;
      default:
	      throw new GeneralSecurityException("Invalid policy");
      }
    }
    catch (GeneralSecurityException gse) {
      if (log.isWarnEnabled()) {
      	log.warn("Unable to unprotect object: " + source.toAddress()
      		 + " -> " + target.toAddress() + " - policy=" + method);
      }
      throw gse;
    }
    return theObject;
  }

  private PublicKeyEnvelope sign(Serializable object,
				 MessageAddress source,
				 MessageAddress target,
				 SecureMethodParam policy)
    throws GeneralSecurityException, IOException {
    if (log.isDebugEnabled()) {
      log.debug("Sign object: " + source.toAddress()
			 + " -> " + target.toAddress());
    }
    // Find source certificate
    X509Certificate sender = keyRing.findFirstAvailableCert(source.toAddress());
    SignedObject signedObject = sign(source.toAddress(), policy.signSpec, object);

    PublicKeyEnvelope pke =
      new PublicKeyEnvelope(sender, null, policy, null, null, signedObject);
    return pke;
  }

  private PublicKeyEnvelope encrypt(Serializable object,
				    MessageAddress source,
				    MessageAddress target,
				    SecureMethodParam policy)
    throws GeneralSecurityException, IOException {
    if (log.isDebugEnabled()) {
      log.debug("Encrypt object: " + source.toAddress()
			 + " -> " + target.toAddress());
    }
    PublicKeyEnvelope pke = null;

    // Find target & receiver certificates
    X509Certificate receiver = keyRing.findFirstAvailableCert(target.toAddress());
    X509Certificate sender = keyRing.findFirstAvailableCert(source.toAddress());

    /* Have we already generated a session key for this pair of agents? */
    MessageAddressPair mp = new MessageAddressPair(source.toAddress(), target.toAddress(),
						   sender, receiver);
    SessionKeySet so = (SessionKeySet) sessionKeys.get(mp);
    SealedObject secret = null;
    SealedObject secretSender = null;
    SecretKey sk = null;
    if (so == null) {
      /*generate the secret key*/
      int i = policy.symmSpec.indexOf("/");
      String a;
      a =  i > 0 ? policy.symmSpec.substring(0,i) : policy.symmSpec;
      SecureRandom random = new SecureRandom();
      KeyGenerator kg = KeyGenerator.getInstance(a);
      kg.init(random);
      sk = kg.generateKey();

      // Encrypt session key
      secret = asymmEncrypt(target.toAddress(), policy.asymmSpec, sk, receiver);
      secretSender = asymmEncrypt(source.toAddress(), policy.asymmSpec, sk, sender);
      SessionKeySet sks = new SessionKeySet(secretSender, secret, sk);
      sessionKeys.put(mp, sks);
    }
    else {
      secret = so.receiver;
      secretSender = so.sender;
      sk = so.secretKey;
    }
    SealedObject sealedMsg = symmEncrypt(sk, policy.symmSpec, object);

    pke = new PublicKeyEnvelope(null, receiver, policy, secret, secretSender, sealedMsg);
    return pke;
  }

  private PublicKeyEnvelope signAndEncrypt(Serializable object,
					   MessageAddress source,
					   MessageAddress target,
					   SecureMethodParam policy)
    throws GeneralSecurityException, IOException {
    if (log.isDebugEnabled()) {
      log.debug("Sign&Encrypt object: " + source.toAddress()
			 + " -> " + target.toAddress());
    }

    PublicKeyEnvelope envelope = null;
    /* Generate the secret key */
    int i = policy.symmSpec.indexOf("/");
    String a;
    a =  i > 0 ? policy.symmSpec.substring(0,i) : policy.symmSpec;
    if(log.isDebugEnabled()) {
      log.debug("Secret Key Parameters: " + a);
    }
    SecureRandom random = new SecureRandom();
    KeyGenerator kg=KeyGenerator.getInstance(a);
    kg.init(random);
    SecretKey sk=kg.generateKey();

    SealedObject sessionKey = null;
    SealedObject sessionKeySender = null;
    SealedObject sealedObject = null;
    SignedObject signedObject = null;

    if(log.isDebugEnabled()) {
      log.debug("Encrypting session key with "
		+ target.toAddress() + " certificate");
    }
    // Find source & target certificate
    X509Certificate sender = keyRing.findFirstAvailableCert(source.toAddress());
    X509Certificate receiver = keyRing.findFirstAvailableCert(target.toAddress());

    // Encrypt session key
    sessionKey = asymmEncrypt(target.toAddress(), policy.asymmSpec, sk, receiver);
    // Encrypt session key with sender key
    sessionKeySender = asymmEncrypt(source.toAddress(), policy.asymmSpec, sk, sender);

    if(log.isDebugEnabled()) {
      log.debug("Signing object with " + source.toAddress() + " key");
    }
    // Sign object
    signedObject = sign(source.toAddress(), policy.signSpec, object);

    if(log.isDebugEnabled()) {
      log.debug("Encrypting object");
    }
    // Encrypt object
    sealedObject = symmEncrypt(sk, policy.symmSpec, signedObject);

    if(log.isDebugEnabled()) {
      log.debug("Looking up source & target certificate");
    }

    if(log.isDebugEnabled()) {
      log.debug("Creating secure envelope");
    }

    envelope =
      new PublicKeyEnvelope(sender, receiver, policy,
			    sessionKey, sessionKeySender, sealedObject);
    return envelope;
  }

  /** Return the secret key of a protected object.
   * The session key should have been encrypted with both the source
   * and the target.
   */
  private SecretKey getSecretKey(MessageAddress source,
				 MessageAddress target,
				 PublicKeyEnvelope envelope,
				 SecureMethodParam policy) {
    SecretKey sk = null;
    /* The object was encrypted for a remote agent. However,
     * the remote agent may not be able to process that message, and
     * the source agent wants to get the object back.
     * There could be multiple reasons why the remote agent
     * did not process the object: the infrastructure was
     * not able to send the message, the remote agent did
     * not accept the message, etc.
     */
    if (envelope.getEncryptedSymmetricKey() == null) {
      log.warn("EncryptedSymmetricKey of receiver null");
    }
    sk = (SecretKey)
      asymmDecrypt(target.toAddress(), policy.asymmSpec,
		   envelope.getEncryptedSymmetricKey());
    if (sk == null) {
      // Try with the source address
      if (envelope.getEncryptedSymmetricKeySender() == null) {
        log.warn("EncryptedSymmetricKey of sender null");
      }
      sk = (SecretKey)
	asymmDecrypt(source.toAddress(), policy.asymmSpec,
		     envelope.getEncryptedSymmetricKeySender());
    }
    return sk;
  }

  private Object decryptAndVerify(MessageAddress source,
				  MessageAddress target,
				  PublicKeyEnvelope envelope,
				  SecureMethodParam policy)
    throws GeneralSecurityException {
    if (log.isDebugEnabled()) {
      log.debug("Decrypt&verify object: " + source.toAddress()
			 + " -> " + target.toAddress());
    }

    // Retrieve the secret key, which was encrypted using the public key
    // of the target.
    if(log.isDebugEnabled()) {
      log.debug("Retrieving secret key");
    }
    SecretKey sk = getSecretKey(source, target, envelope, policy);
    if (sk == null) {
      if (log.isErrorEnabled()) {
        log.error("DecryptAndVerify: unable to retrieve secret key. Msg:" + source.toAddress()
		  + " -> " + target.toAddress());
      }
      throw new GeneralSecurityException("can't get secret key.");
    }

    if(log.isDebugEnabled()) {
      log.debug("Decrypting object");
    }
    // Decrypt the object
    SignedObject signedObject =
      (SignedObject)symmDecrypt(sk, (SealedObject)envelope.getObject());

    if(log.isDebugEnabled()) {
      log.debug("Verifying signature");
    }
    // Verify the signature
    Object o = null;
    try {
      o = verify(source.toAddress(), policy.signSpec, signedObject);
    }
    catch (CertificateException e) {
      if(log.isErrorEnabled()) {
	      log.error("Signature verification failed");
      }
      throw e;
    }
    return o;
  }

  private Object decrypt(MessageAddress source,
			 MessageAddress target,
			 PublicKeyEnvelope envelope,
			 SecureMethodParam policy)
    throws GeneralSecurityException {
    if (log.isDebugEnabled()) {
      log.debug("Decrypt object: " + source.toAddress()
			 + " -> " + target.toAddress());
    }

    // Retrieving the secret key, which was encrypted using the public key
    // of the target.
    SecretKey sk = getSecretKey(source, target, envelope, policy);
    if (sk == null) {
      if (log.isErrorEnabled()) {
	log.error("Error: unable to retrieve secret key");
      }
      return null;
    }
    // Decrypt the object
    Object o =
      symmDecrypt(sk, (SealedObject)envelope.getObject());
    return o;
  }

  private Object verify(MessageAddress source,
			MessageAddress target,
			PublicKeyEnvelope envelope,
			SecureMethodParam policy)
    throws GeneralSecurityException {
    if (log.isDebugEnabled()) {
      log.debug("Verify object: " + source.toAddress()
			 + " -> " + target.toAddress());
    }
    // Verify the signature
    Object o = null;
    o = verify(source.toAddress(), policy.signSpec,
	       (SignedObject)envelope.getObject());
    return o;
  }

  public ProtectedObject protectObject(Serializable object,
				       MessageAddress source,
				       MessageAddress target,
				       CryptoPolicy cp)
    throws GeneralSecurityException, IOException{
    if (object == null) {
      throw new IllegalArgumentException("Object to protect is null");
    }
    if (source == null) {
      throw new IllegalArgumentException("Source not specified");
    }
    if (target == null) {
      throw new IllegalArgumentException("Target not specified");
    }
    if (cp == null) {
      throw new IllegalArgumentException("Policy not specified");
    }
    String failureIfOccurred = MessageFailureEvent.UNKNOWN_FAILURE;
    try {
      /* assembly SecureMethodParam:
       * as CryptoPolicy can contain multiple entries for each parameter,
       * every meaningful combinations needs to be checked before declare
       * a failure, i.e. throwing IOException
       */
      SecureMethodParam smp = new SecureMethodParam();
      String method = "";
      ProtectedObject po = null;
      Iterator iter = (cp.getSecuMethod(target.toAddress())).iterator();
      while(iter.hasNext()){
        method = (String)iter.next();
        if(method.equalsIgnoreCase("plain")){
          smp.secureMethod = SecureMethodParam.PLAIN;
          po = getProtection(object,source,target,smp,iter.hasNext());
          if(po!=null) return po;
        }else if(method.equalsIgnoreCase("sign")){
          smp.secureMethod = SecureMethodParam.SIGN;
          failureIfOccurred = MessageFailureEvent.SIGNING_FAILURE;
          Iterator iter2 = (cp.getSignSpec(target.toAddress())).iterator();
          while(iter2.hasNext()){
            smp.signSpec = (String)iter2.next();
            po = getProtection(object, source,target,smp,
                        iter.hasNext() && iter2.hasNext());
            if(po!=null) return po;
          }
        }else if(method.equalsIgnoreCase("encrypt")){
          smp.secureMethod = SecureMethodParam.ENCRYPT;
          failureIfOccurred = MessageFailureEvent.ENCRYPT_FAILURE;
          Iterator iter2 = (cp.getSymmSpec(target.toAddress())).iterator();
          while(iter2.hasNext()){
            smp.symmSpec = (String)iter2.next();
            Iterator iter3 = (cp.getAsymmSpec(target.toAddress())).iterator();
            while(iter3.hasNext()){
              smp.asymmSpec = (String)iter3.next();
              po = getProtection(object, source,target,smp,
                iter.hasNext() && iter2.hasNext() && iter3.hasNext());
              if(po!=null) return po;
            }
          }
        }else if(method.equalsIgnoreCase("signAndEncrypt")){
          smp.secureMethod = SecureMethodParam.SIGNENCRYPT;
          failureIfOccurred = MessageFailureEvent.SIGN_AND_ENCRYPT_FAILURE;
          Iterator iter2 = (cp.getSymmSpec(target.toAddress())).iterator();
          while(iter2.hasNext()){
            smp.symmSpec = (String)iter2.next();
            Iterator iter3 = (cp.getAsymmSpec(target.toAddress())).iterator();
            while(iter3.hasNext()){
              smp.asymmSpec = (String)iter3.next();
              Iterator iter4 = (cp.getSignSpec(target.toAddress())).iterator();
              while(iter4.hasNext()){
                smp.signSpec = (String)iter4.next();
                po = getProtection(object, source,target,smp,
                  iter.hasNext() && iter2.hasNext()
                    && iter3.hasNext() && iter4.hasNext());
                if(po!=null) return po;
              }
            }
          }
        }else{
          smp.secureMethod = SecureMethodParam.INVALID;
          if (log.isErrorEnabled()) {
            log.error("outputStream NOK: " + source.toAddress()
               + " -> " + target.toAddress()
               + "invalid secure method.");
          }
          failureIfOccurred = MessageFailureEvent.INVALID_POLICY;
          throw new GeneralSecurityException("invalid secure method.");
        }
      }//while
    }
    catch(GeneralSecurityException gse) {
      String message = failureIfOccurred + " - " + gse.getMessage();
      throw new GeneralSecurityException(message);
    }

    //fall through
    if (log.isErrorEnabled()) {
      log.error("OutputStream NOK: " + source.toAddress()
         + " -> " + target.toAddress()
         + "none of the crypto parameter works: " + cp.toString());
    }
    String message = MessageFailureEvent.INVALID_POLICY + " - failed protecting object.";
    throw new GeneralSecurityException(message);
  }

  public Object unprotectObject(MessageAddress source,
				MessageAddress target,
				ProtectedObject protectedObject,
				CryptoPolicy cp)
    throws GeneralSecurityException, IOException{
    if (protectedObject == null) {
      throw new IllegalArgumentException("Object to unprotect is null");
    }
    if (source == null) {
      throw new IllegalArgumentException("Source not specified");
    }
    if (target == null) {
      throw new IllegalArgumentException("Target not specified");
    }
    if (cp == null) {
      throw new IllegalArgumentException("Policy not specified");
    }
    String failureIfOccurred = MessageFailureEvent.UNKNOWN_FAILURE;
    try {
      /* assembly SecureMethodParam:
       * as CryptoPolicy can contain multiple entries for each parameter,
       * every meaningful combinations needs to be checked before declare
       * a failure, i.e. throwing IOException
       */
      SecureMethodParam smp = new SecureMethodParam();
      String method = "";
      Object rawData = null;
      Iterator iter = (cp.getSecuMethod(source.toAddress())).iterator();
      while(iter.hasNext()){
        method = (String)iter.next();
        if(method.equalsIgnoreCase("plain")){
          smp.secureMethod = SecureMethodParam.PLAIN;
          if (smp.secureMethod == protectedObject.getSecureMethod().secureMethod){
            rawData = getRawData(protectedObject,source,target,smp,iter.hasNext());
            if(rawData!=null) return rawData;
          }
        }else if(method.equalsIgnoreCase("sign")){
          smp.secureMethod = SecureMethodParam.SIGN;
          failureIfOccurred = MessageFailureEvent.VERIFICATION_FAILURE;
          if (smp.secureMethod == protectedObject.getSecureMethod().secureMethod){
            Iterator iter2 = (cp.getSignSpec(source.toAddress())).iterator();
            while(iter2.hasNext()){
              smp.signSpec = (String)iter2.next();
              rawData = getRawData(protectedObject, source,target,smp,
                          iter.hasNext() && iter2.hasNext());
              if(rawData!=null) return rawData;
            }
          }
        }else if(method.equalsIgnoreCase("encrypt")){
          smp.secureMethod = SecureMethodParam.ENCRYPT;
          failureIfOccurred = MessageFailureEvent.DECRYPT_FAILURE;
          if (smp.secureMethod == protectedObject.getSecureMethod().secureMethod){
            Iterator iter2 = (cp.getSymmSpec(source.toAddress())).iterator();
            while(iter2.hasNext()){
              smp.symmSpec = (String)iter2.next();
              Iterator iter3 = (cp.getAsymmSpec(source.toAddress())).iterator();
              while(iter3.hasNext()){
                smp.asymmSpec = (String)iter3.next();
                rawData = getRawData(protectedObject, source,target,smp,
                  iter.hasNext() && iter2.hasNext() && iter3.hasNext());
                if(rawData!=null) return rawData;
              }
            }
          }
        }else if(method.equalsIgnoreCase("signAndEncrypt")){
          smp.secureMethod = SecureMethodParam.SIGNENCRYPT;
          failureIfOccurred = MessageFailureEvent.DECRYPT_AND_VERIFY_FAILURE;
          if (smp.secureMethod == protectedObject.getSecureMethod().secureMethod){
            Iterator iter2 = (cp.getSymmSpec(source.toAddress())).iterator();
            while(iter2.hasNext()){
              smp.symmSpec = (String)iter2.next();
              Iterator iter3 = (cp.getAsymmSpec(source.toAddress())).iterator();
              while(iter3.hasNext()){
                smp.asymmSpec = (String)iter3.next();
                Iterator iter4 = (cp.getSignSpec(source.toAddress())).iterator();
                while(iter4.hasNext()){
                  smp.signSpec = (String)iter4.next();
                  rawData = getRawData(protectedObject, source,target,smp,
                    iter.hasNext() && iter2.hasNext()
                      && iter3.hasNext() && iter4.hasNext());
                  if(rawData!=null) return rawData;
                }
              }
            }
          }
        }else{
          smp.secureMethod = SecureMethodParam.INVALID;
          if (log.isErrorEnabled()) {
            log.error("readInputStream NOK: " + source.toAddress()
               + " -> " + target.toAddress()
               + "invalid secure method.");
          }
          failureIfOccurred = MessageFailureEvent.INVALID_POLICY;
          throw new GeneralSecurityException("invalid secure method.");
        }
      }//while
    }
    catch(GeneralSecurityException gse) {
      // need to format exception message inorder to determine the
      // the reason for the failure
      String message = failureIfOccurred + " - " + gse.getMessage();
      throw new GeneralSecurityException(message);
    }

    //fall through
    if (log.isErrorEnabled()) {
      log.error("readInputStream NOK: " + source.toAddress()
         + " -> " + target.toAddress()
         + "none of the crypto parameter works: " + cp.toString());
    }
    String message = MessageFailureEvent.INVALID_POLICY + " - failed unprotecting object.";
    throw new GeneralSecurityException(message);
  }//unprotectObj

  private Object getRawData(ProtectedObject obj,
				       MessageAddress source,
				       MessageAddress target,
              SecureMethodParam policy, boolean goOn)
              throws GeneralSecurityException, IOException
  {
    try {
      return unprotectObject(source,
               target,
               obj, policy);
    }
    catch (GeneralSecurityException gse) {
      if(goOn) return null;
      if (log.isWarnEnabled()) {
        log.warn("readInputStream NOK: " + source.toAddress()
           + " -> " + target.toAddress()
           + gse);
      }
      throw gse;
    }
  }//getRawData

  private ProtectedObject getProtection(Serializable obj,
				       MessageAddress source,
				       MessageAddress target,
              SecureMethodParam policy, boolean goOn)
              throws GeneralSecurityException, IOException
  {
    try {
      return protectObject(obj, source, target, policy);
    }
    catch (GeneralSecurityException gse) {
      if(goOn) return null;
      if (log.isWarnEnabled()) {
        log.warn("put OutputStream NOK: " + source.toAddress()
           + " -> " + target.toAddress()
           + gse);
      }
      throw gse;
    }
  }//getProtection

  private class MessageAddressPair
  {
    private String source;
    private String target;
    private X509Certificate sender;
    private X509Certificate receiver;

    public MessageAddressPair(String src, String tgt,
			      X509Certificate snd,
			      X509Certificate rcv) {
      if (src == null || tgt == null || snd == null || rcv == null) {
	throw new IllegalArgumentException("One of the parameters is null");
      }
      source = src;
      target = tgt;
      sender = snd;
      receiver = rcv;
    }

    public boolean equals(Object o) {
      MessageAddressPair mp = null;
      if (!(o instanceof MessageAddressPair)) {
	return false;
      }
      else {
	mp = (MessageAddressPair) o;
      }
      if (mp.source.equals(source)
	  && mp.target.equals(target)
	  && mp.sender.equals(sender)
	  && mp.receiver.equals(receiver)) {
	return true;
      }
      return false;
    }
  }

  private class SessionKeySet {
    public SessionKeySet(SealedObject snd, SealedObject rcv, SecretKey sk) {
      sender = snd;
      receiver = rcv;
      secretKey = sk;
    }

    public SealedObject sender;
    public SealedObject receiver;
    public SecretKey secretKey;
  }
}
