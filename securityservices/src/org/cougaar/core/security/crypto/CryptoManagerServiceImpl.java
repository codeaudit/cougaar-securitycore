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

import java.io.*;
import java.security.*;
import java.util.*;
import java.security.cert.*;
import javax.crypto.*;
import sun.security.x509.*;
import java.text.MessageFormat;
import java.text.ParseException;

// Cougaar core infrastructure
import org.cougaar.core.component.ServiceRevokedListener;
import org.cougaar.core.component.ServiceRevokedEvent;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.mts.ProtectedOutputStream;
import org.cougaar.core.mts.ProtectedInputStream;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.security.monitoring.publisher.EventPublisher;
import org.cougaar.core.security.crypto.CertificateChainException;

// Cougaar Security Services
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.crypto.PublicKeyEnvelope;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.monitoring.event.MessageFailureEvent;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.policy.CryptoPolicy;
import org.cougaar.core.security.util.DumpOutputStream;
import org.cougaar.core.security.util.SignatureOutputStream;
import org.cougaar.core.security.util.SignatureInputStream;
import org.cougaar.core.security.util.ErasingMap;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;

public class CryptoManagerServiceImpl
  implements EncryptionService
{
  private static final MessageFormat MF = new MessageFormat("{0} -");
  public final static String DUMP_PROPERTY =
    "org.cougaar.core.security.crypto.dumpMessages";
  /** Set to true to dump messages to a file (for debug purposes) */
  private static final boolean DUMP_MESSAGES = 
    Boolean.getBoolean(DUMP_PROPERTY);
  private static final long RANDOM = (new Random()).nextLong();
  private static int        _fileno = 10000;
  private static final int DEFAULT_INIT_BUFFER_SIZE = 200;

  private KeyRingService keyRing;
  private ServiceBroker serviceBroker;
  private LoggingService log;
  private Hashtable ciphers = new Hashtable();
  private Map _sent = new ErasingMap();

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

  private PrivateKey getPrivateKey(String name) 
    throws GeneralSecurityException, IOException {
    return (PrivateKey) getPrivateKeys(name).iterator().next();
  }

  private List getPrivateKeys(final String name) 
    throws GeneralSecurityException, IOException {
    List pkList = (List)
      AccessController.doPrivileged(new PrivilegedAction() {
          public Object run(){
            // relieve messages to naming, for local keys
            // do not need to go to naming
//             List nameList = keyRing.getX500NameFromNameMapping(name);
            List nameList = keyRing.findDNFromNS(name);
            if (log.isDebugEnabled()) {
              log.debug("List of names for " + name + ": " + nameList);
            }
            List keyList = new ArrayList();
            for (int i = 0; i < nameList.size(); i++) {
              X500Name dname = (X500Name)nameList.get(i);
              List pkCerts = keyRing.findPrivateKey(dname);
              Iterator iter = pkCerts.iterator();
              while (iter.hasNext()) {
                PrivateKeyCert pkc = (PrivateKeyCert) iter.next();
                keyList.add(pkc.getPrivateKey());
              }
            }
            return keyList;
          }
        });
    if (pkList == null || pkList.size() == 0) {
      String message = "Unable to get private key of " + 
        name + " -- does not exist.";
      if (log.isWarnEnabled()) {
        log.warn(message);
      }
      throw new NoValidKeyException("Private key of " + name + " not found");
    }
    return pkList;
  }

  public SignedObject sign(String name,
			   String spec,
			   Serializable obj)
    throws GeneralSecurityException, IOException {
    PrivateKey pk = getPrivateKey(name);
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
    cipherTry++;
    if (log.isDebugEnabled()) {
      if (cipherTry != 0 && ((cipherTry % 100) == 0)) {
        log.debug("cipher try: " + cipherTry + " hit: " + cipherHit + " return: " + cipherReturn);
      }
    }

    synchronized (this.ciphers) {
      list = (ArrayList) this.ciphers.get(spec);
      if (list == null) {
        list = new ArrayList();
        this.ciphers.put(spec,list);
      }
    }

    synchronized (list) {
      if (!list.isEmpty()) {
        cipherHit++;
        return (Cipher) list.remove(list.size() - 1);
      }
    }
    return Cipher.getInstance(spec);
  }

  public void returnCipher(String spec, Cipher cipher) {
    ArrayList list;
    cipherReturn++;
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
    ArrayList signatureIssues = new ArrayList();
    if (obj == null) {
      throw new IllegalArgumentException("Signed object with " + name
					 + " key is null. Unable to verify signature");
    }
    // need to find all certs with the name signed by multiple CAs
    List nameList = keyRing.findDNFromNS(name);

    int lookupFlags[] = { KeyRingService.LOOKUP_KEYSTORE |
                          KeyRingService.LOOKUP_LDAP,
                          KeyRingService.LOOKUP_KEYSTORE |
                          KeyRingService.LOOKUP_LDAP |
                          KeyRingService.LOOKUP_FORCE_LDAP_REFRESH };

    for (int i = 0; i < nameList.size(); i++) {
      X500Name dname = (X500Name)nameList.get(i);

      for (int j = 0; j < lookupFlags.length; j++) {
        List certList = keyRing.findCert(dname, lookupFlags[j], !expiredOk);
        if (certList == null || certList.size() == 0) {
          if (j < lookupFlags.length - 1) {
            continue;
          } // end of if (j < lookupFlags.length -1)

          if (log.isWarnEnabled()) {
            log.warn("Unable to verify object. Certificate of " + dname
                   + " does not exist.");
          }
          throw new NoValidKeyException("Unable to get certificate of "
                                      + dname);
        }

        Object o = verify(certList, obj, expiredOk, signatureIssues);
        if (o != null)
	  return o;
      }

    }
    // No suitable certificate was found.
    if (log.isWarnEnabled()) {
      log.warn("Signature verification failed. Agent=" + name);
	//+ " - Tried with " + certList.size() + " certificates");
      for (int i = 0 ; i < signatureIssues.size() ; i++) {
	log.warn((String) signatureIssues.get(i));
      }
    }
    throw new NoValidKeyException("Unable to get certificate of "
                                  + name);
  }

  private Object verify(List certList, SignedObject obj, boolean expiredOk, ArrayList signatureIssues) 
    throws CertificateException {
    Iterator it = certList.iterator();

    while (it.hasNext()) {
      CertificateStatus cs = (CertificateStatus)it.next();
      java.security.cert.Certificate c = cs.getCertificate();
      try {
	// filter out those non valid certificates first
        if (expiredOk) {
          try {
            keyRing.checkCertificateTrust((X509Certificate)c);
          } catch (CertificateException ce) {
	    signatureIssues.add("Certificate trust exception:" + ce
				+ ". Certificate:" + (X509Certificate)c);
            if (!(ce instanceof CertificateExpiredException)) {
              continue;
	    }
            if (log.isDebugEnabled()) {
              log.debug("Certificate has expired." + cs.getCertificateAlias());
	    }
          }
        }

	PublicKey pk = c.getPublicKey();
	Signature ve;
	//if(spec==null||spec=="")spec=pk.getAlgorithm();
	String spec = AlgorithmParam.getSigningAlgorithm(pk.getAlgorithm());
	if (spec == null) {
	  log.warn("Unable to retrieve Algorithm specification from key");
	  signatureIssues.add("Unable to retrieve Algorithm specification from key. Certificate:"
			      + (X509Certificate)c);
	  continue;
	}
	ve=Signature.getInstance(spec);
	if (obj.verify(pk,ve)) {
	  return obj.getObject();
	} else {
	  // That's OK. Maybe there is an old certificate which is not
	  // trusted anymore, but we may have a newer one too.
	  signatureIssues.add("Verification failure. Certificate:" + ((X509Certificate)c).toString());
	  continue;
	}
      } catch (Exception e) {
	// That's OK. Maybe there is an old certificate which is not
	// trusted anymore, but we may have a newer one too.
	signatureIssues.add("Unable to verify signature:" + e + ". Certificate:" + (X509Certificate)c);

	if (log.isInfoEnabled()) {
	  log.info("Unable to verify signature", e);
	}
	continue;
      }
    }
    return null;
  }

  public SealedObject asymmEncrypt(String name, String spec, Serializable obj,
				   java.security.cert.Certificate cert)
    throws GeneralSecurityException, IOException {
    /*encrypt the secret key with receiver's public key*/

    PublicKey key = cert.getPublicKey();

    if (spec==""||spec==null) {
      spec=key.getAlgorithm();
    }
    if (log.isDebugEnabled()) {
      log.debug("Encrypting for " + name + " using " + spec);
    }
    /*init the cipher*/
    Cipher ci = getCipher(spec);
    try {
      ci.init(Cipher.ENCRYPT_MODE,key);
      SealedObject so = new SealedObject(obj,ci);
      return so;
    }
    finally {
      if (ci != null) {
        returnCipher(spec,ci);
      }
    }
  }

  public Object asymmDecrypt(String name,
			     String spec,
			     SealedObject obj) {
    // get secret keys
    List keyList;
    try {
      keyList = getPrivateKeys(name);
    } catch (Exception e) {
      log.warn("Cannot recover message", e);
      return null;
    }
    Iterator it = keyList.iterator();
    PrivateKey key = null;
    Cipher ci = null;
    while (it.hasNext()) {
      key = (PrivateKey)it.next();
      if(spec==null||spec=="")
	spec=key.getAlgorithm();
      try {
	ci=getCipher(spec);
        ci.init(Cipher.DECRYPT_MODE, key);
        Object o = obj.getObject(ci);
        return o;
      } catch (Exception e) {
	// That's OK. Maybe there is an old certificate which is not
	// trusted anymore, but we may have a newer one too.
	if (log.isInfoEnabled()) {
          if (it.hasNext()) {
            log.info("Cannot recover message. " + e +
                     ". Trying with next certificate...");
          } else {
            log.warn("Cannot recover message. No other certificates are available. ",
                     e);
          }
	}
	continue;
      } finally {
        if (ci != null) {
          returnCipher(spec,ci);
        }
      }
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
    try {
      ci.init(Cipher.ENCRYPT_MODE,sk);
      SealedObject so = new SealedObject(obj,ci);
      return so;
    }
    finally {
      if (ci != null) {
        returnCipher(spec,ci);
      }
    }
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
    Cipher ci = null;
    try{
      ci = getCipher(alg);
      ci.init(Cipher.DECRYPT_MODE, sk);
      o = obj.getObject(ci);
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
          ci.init(Cipher.DECRYPT_MODE, sk);
          o = obj.getObject(ci);
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
    finally {
      if (ci != null) {
        returnCipher(alg,ci);
      }
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
	throw new GeneralSecurityException("Invalid policy:" + policy.getSecureMethodToString());
      }
    }
    catch (GeneralSecurityException gse) {
      if (gse instanceof CertificateException) {
        if (log.isDebugEnabled()) {
          log.debug("Unable to protect object: " + source.toAddress()
                   + " -> " + target.toAddress() + " - policy=" + method);
        }
      }
      else {
        if (log.isWarnEnabled()) {
          log.warn("Unable to protect object: " + source.toAddress()
                   + " -> " + target.toAddress() + " - policy=" + method);
        }
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
	      throw new GeneralSecurityException("Invalid policy:" + policy.getSecureMethodToString());
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
    //X509Certificate sender = keyRing.findFirstAvailableCert(source.toAddress());
    SignedObject signedObject = sign(source.toAddress(), policy.signSpec, object);

    PublicKeyEnvelope pke =
      new PublicKeyEnvelope(null, null, source, target, policy, null, null, signedObject);
    return pke;
  }

  private SessionKeySet getSessionKeySet(MessageAddress source,
				    MessageAddress target,
				    SecureMethodParam policy)
    throws GeneralSecurityException, IOException {
    skeyTry++;
    if (skeyTry != 0 && ((skeyTry % 50) == 0)) {
      log.debug("encrypt key try: " + skeyTry + " hit: " + skeyHit);
    }

    /* Have we already generated a session key for this pair of agents? */
    Hashtable targets;

    synchronized (sessionKeys) {
      targets = (Hashtable) sessionKeys.get(source.toAddress());
      if (targets == null) {
	targets = new Hashtable();
	sessionKeys.put(source.toAddress(), targets);
      }
    }

    synchronized (targets) {
      SessionKeySet so = (SessionKeySet) targets.get(target.toAddress());
      // Find target & receiver certificates
      Hashtable certTable = keyRing.findCertPairFromNS(source.toAddress(), target.toAddress());
      X509Certificate sender = (X509Certificate)certTable.get(source.toAddress());
      X509Certificate receiver = (X509Certificate)certTable.get(target.toAddress());
      if (sender == null) {
	String msg = "Cannot create session key. Sender certificate not found: "
	  + source.toAddress();
	if (log.isDebugEnabled()) {
	  log.debug(msg);
	}
	throw new CertificateException(msg);
      }
      if (receiver == null) {
	String msg = "Cannot create session key. Receiver certificate not found: "
	  + target.toAddress();
	if (log.isDebugEnabled()) {
	  log.debug(msg);
	}
	throw new CertificateException(msg);
      }
      if (so == null || !so.receiverCert.equals(receiver) ||
          !so.senderCert.equals(sender)) {
	/*generate the secret key*/
	int i = policy.symmSpec.indexOf("/");
	String a;
	a =  i > 0 ? policy.symmSpec.substring(0,i) : policy.symmSpec;
	SecureRandom random = new SecureRandom();
	KeyGenerator kg = KeyGenerator.getInstance(a);
	kg.init(random);
	SecretKey sk = kg.generateKey();


	// Encrypt session key
	SealedObject secret = asymmEncrypt(target.toAddress(), policy.asymmSpec, sk, receiver);
	SealedObject secretSender = asymmEncrypt(source.toAddress(), policy.asymmSpec, sk, sender);
	so = new SessionKeySet(secretSender, secret, sk, secret, secretSender,
                               sender, receiver);
	targets.put(target.toAddress(), so);
      }
      else {
	skeyHit++;
      }
      return so;
    }
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

    SessionKeySet so = getSessionKeySet(source, target, policy);
    SealedObject secret = so.receiver;
    SealedObject secretSender = so.sender;
    SecretKey sk = so.secretKey;
    SealedObject sealedMsg = symmEncrypt(sk, policy.symmSpec, object);

    pke = new PublicKeyEnvelope(null, null, source, target, policy, secret, secretSender, sealedMsg);
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

    SessionKeySet so = getSessionKeySet(source, target, policy);
    SealedObject secret = so.receiver;
    SealedObject secretSender = so.sender;
    SecretKey sk = so.secretKey;

    if(log.isDebugEnabled()) {
      log.debug("Signing object with " + source.toAddress() + " key");
    }
    // Sign object
    SignedObject signedObject = sign(source.toAddress(), policy.signSpec, object);

    if(log.isDebugEnabled()) {
      log.debug("Encrypting object");
    }
    // Encrypt object
    SealedObject sealedObject = symmEncrypt(sk, policy.symmSpec, signedObject);

    if(log.isDebugEnabled()) {
      log.debug("Looking up source & target certificate");
    }

    if(log.isDebugEnabled()) {
      log.debug("Creating secure envelope");
    }

    envelope =
      new PublicKeyEnvelope(null, null, source, target, policy,
			    secret, secretSender, sealedObject);
    return envelope;
  }

  int cipherTry = 0;
  int cipherHit = 0;
  int cipherReturn = 0;
  int keyTry = 0;
  int keyHit = 0;
  int skeyTry = 0;
  int skeyHit = 0;

  /** Return the secret key of a protected object.
   * The session key should have been encrypted with both the source
   * and the target.
   */
  private SecretKey getSecretKey(MessageAddress source,
				 MessageAddress target,
				 PublicKeyEnvelope envelope,
				 SecureMethodParam policy)
    throws GeneralSecurityException, IOException {
    SecretKey sk = null;

    keyTry++;
    if (keyTry != 0 && ((keyTry % 50) == 0)) {
      log.debug("decrypt try: " + keyTry + " hit: " + keyHit);
    }

    Hashtable targets;

    synchronized (sessionKeys) {
      targets = (Hashtable) sessionKeys.get(source.toAddress());
      if (targets == null) {
	targets = new Hashtable();
	sessionKeys.put(source.toAddress(), targets);
      }
    }

    synchronized (targets) {
      SessionKeySet so = (SessionKeySet) targets.get(target.toAddress());
      if (so != null) {
	keyHit++;
	if (!so.receiverSecretKey.equals(envelope.getEncryptedSymmetricKey()) &&
	    !so.senderSecretKey.equals(envelope.getEncryptedSymmetricKey())) {
	  so = null; // The key used is actually different - reset it.
	} else {
	  sk = so.secretKey;
	}
      }
      if (sk != null) {
	return sk;
      }

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

      //X509Certificate receiver = keyRing.findFirstAvailableCert(target.toAddress());
      //X509Certificate sender = keyRing.findFirstAvailableCert(source.toAddress());
        Hashtable certTable = keyRing.findCertPairFromNS(source.toAddress(), target.toAddress());
        X509Certificate sender = (X509Certificate)certTable.get(source.toAddress());
        X509Certificate receiver = (X509Certificate)certTable.get(target.toAddress());

      if (sk != null && sender != null && receiver != null) {
	SealedObject secret = asymmEncrypt(target.toAddress(), policy.asymmSpec, sk, receiver);
	SealedObject secretSender = asymmEncrypt(source.toAddress(), policy.asymmSpec, sk, sender);
	SessionKeySet sks = new SessionKeySet(secretSender, secret, sk, secret, secretSender, sender,  receiver);
	targets.put(target.toAddress(), sks);
      }
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
    SecretKey sk = null;
    try {
      sk = getSecretKey(source, target, envelope, policy);
    }
    catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("DecryptAndVerify: " + ex);
      }
    }
    if (sk == null) {
      if (log.isErrorEnabled()) {
        log.error("DecryptAndVerify: unable to retrieve secret key. Msg:" + source.toAddress()
		  + " -> " + target.toAddress());
      }
      throw new DecryptSecretKeyException("can't get secret key.");
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
	log.error("Signature verification failed: " + e);
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
    SecretKey sk = null;
    try {
      sk = getSecretKey(source, target, envelope, policy);
    }
    catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("Decrypt: " + ex);
      }
    }
    if (sk == null) {
      if (log.isErrorEnabled()) {
	log.error("Error: unable to retrieve secret key");
      }
      throw new DecryptSecretKeyException("can't get secret key.");
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
        } else {
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
					SecureMethodParam policy,
					boolean goOn)
    throws GeneralSecurityException, IOException
  {
    try {
      return protectObject(obj, source, target, policy);
    }
    catch (GeneralSecurityException gse) {
      if(goOn) {
	return null;
      }
      // if cannot find certificate, only put debug message
      // this happens frequently before certificate is obtained
      // at system startup time
      if (gse instanceof CertificateException) {
        if (log.isDebugEnabled()) {
          log.debug("put OutputStream NOK: " + source.toAddress()
                   + " -> " + target.toAddress()
                   + gse);
        }
      }
      else {
        if (log.isWarnEnabled()) {
          log.warn("put OutputStream NOK: " + source.toAddress()
                   + " -> " + target.toAddress()
                   + gse);
        }
      }
      throw gse;
    }
  }//getProtection

  private class SessionKeySet {
    public SessionKeySet(SealedObject snd, SealedObject rcv, SecretKey sk,
			 SealedObject eskReceiver, SealedObject eskSender,
                         X509Certificate sndCert, X509Certificate rcvCert) {
      sender = snd;
      receiver = rcv;
      secretKey = sk;
      senderSecretKey = eskSender;
      receiverSecretKey = eskReceiver;
      senderCert = sndCert;
      receiverCert = rcvCert;
    }

    public SealedObject sender;
    public SealedObject receiver;
    public SecretKey secretKey;
    public SealedObject senderSecretKey;
    public SealedObject receiverSecretKey;
    public X509Certificate senderCert;
    public X509Certificate receiverCert;
  }

  private static synchronized int getNextNum() { return _fileno++; }

  private static SecretKey createSecretKey(SecureMethodParam policy)
    throws NoSuchAlgorithmException {
    int i = policy.symmSpec.indexOf("/");
    String a =  (i > 0) 
      ? policy.symmSpec.substring(0,i) 
      : policy.symmSpec;
    SecureRandom random = new SecureRandom();
    KeyGenerator kg = KeyGenerator.getInstance(a);
    kg.init(random);
    return kg.generateKey();
  }

  public ProtectedOutputStream protectOutputStream(OutputStream out,
                                                   SecureMethodParam policy,
                                                   MessageAddress source,
                                                   MessageAddress target,
                                                   boolean encryptedSocket,
                                                   Object link) 
    throws GeneralSecurityException, IOException {
    return new ProtectedMessageOutputStream(out, policy, source, target,
                                            encryptedSocket, link);
  }

  public ProtectedInputStream protectInputStream(InputStream stream,
                                                 MessageAddress source,
                                                 MessageAddress target,
                                                 boolean encryptedSocket,
                                                 Object link,
                                                 CryptoPolicyService cps)
    throws GeneralSecurityException, IOException {
    return new ProtectedMessageInputStream(stream, source, target,
                                           encryptedSocket, link, cps);
  }
    
  private static String getDumpFilename() {
    return "msgDump-" + RANDOM + "-" + getNextNum() + ".dmp";
  }

  private static SecureMethodParam copyPolicy(SecureMethodParam policy) {
    SecureMethodParam newPolicy = new SecureMethodParam();
    newPolicy.secureMethod = policy.secureMethod;
    newPolicy.symmSpec = policy.symmSpec;
    newPolicy.asymmSpec = policy.asymmSpec;
    newPolicy.signSpec = policy.signSpec;
    return newPolicy;
  }

  private static void removeEncrypt(SecureMethodParam policy) {
    if (policy.secureMethod == policy.ENCRYPT) {
      policy.secureMethod = policy.PLAIN;
    } else if (policy.secureMethod == policy.SIGNENCRYPT) {
      policy.secureMethod = policy.SIGN;
    }
  }

  private static void removeSign(SecureMethodParam policy) {
    if (policy.secureMethod == policy.SIGN) {
      policy.secureMethod = policy.PLAIN;
    } else if (policy.secureMethod == policy.SIGNENCRYPT) {
      policy.secureMethod = policy.ENCRYPT;
    }
  }

  private Set getSentSet(Object obj) {
    synchronized (_sent) {
      if (log.isDebugEnabled()) {
        log.debug("Checking sent set for " + obj + ", class = " + obj.getClass().getName());
      }
      Set results = (Set) _sent.get(obj);
      if (results == null) {
        results = new HashSet();
        _sent.put(obj, results);
      }
      if (log.isDebugEnabled()) {
        log.debug("Found " + results);
      }
      return results;
    }
  }

  private SecureMethodParam modifyPolicy(SecureMethodParam policy,
                                         boolean encryptedSocket,
                                         Object link,
                                         String source,
                                         String target) {
    policy = copyPolicy(policy);

    // Hack because you might want to MTS yourself a message...
    if (source.equals(target)) {
      policy.secureMethod = policy.PLAIN;
      return policy;
    }

    // SR - 10/21/2002. UGLY & TEMPORARY FIX
    // The advance message clock uses an unsupported address type.
    // Since this is demo-ware, we are not encrypting those messages.
    // The "(MTS)" part is the only ugly part -- GM

    if (encryptedSocket || target.endsWith("(MTS)")) {
      removeEncrypt(policy); // no need for double-encryption
    }

    if (source.startsWith("(MTS)")) {
      // FIXME!! should check the source principal also
      policy.secureMethod = policy.PLAIN;
    }

    if (policy.secureMethod == policy.SIGN && encryptedSocket && 
        link != null) {
      Set sentSet = getSentSet(link);
      synchronized (sentSet) {
        if (sentSet.contains(source)) {
          policy.secureMethod = policy.PLAIN;
        }
      }
    }
    return policy;
  }

  private Collection modifyPolicies(Collection policies,
                                    boolean encryptedSocket,
                                    Object link,
                                    String source,
                                    String target) {
    Collection newPolicies = new LinkedList();
    Iterator iter = policies.iterator();
    while (iter.hasNext()) {
      SecureMethodParam policy = 
        modifyPolicy((SecureMethodParam)iter.next(),
                     encryptedSocket, link, source, target);
      newPolicies.add(policy);
      if (log.isDebugEnabled()) {
        log.debug("Policy from " + source + " to " + target + " = " + policy);
      }
    }
    return newPolicies;
  }

  private void setSent(String source, Object link) {
    if (link != null) {
      Set sentSet = getSentSet(link);
      synchronized (sentSet) {
        sentSet.add(source);
      }
    }
  }

  private class ProtectedMessageOutputStream extends ProtectedOutputStream {
    private SignatureOutputStream _signature;
    private boolean               _eom = false;
    private boolean               _sign;
    private boolean               _encrypt;
    private EventPublisher        _eventPublisher;
    private X509Certificate       _senderCert;
    private Cipher                _cipher;
    private String                _symmSpec;
    private Object                _link;
    private String                _sender;

    public ProtectedMessageOutputStream(OutputStream stream,
                                        SecureMethodParam policy,
                                        MessageAddress source,
                                        MessageAddress target,
                                        boolean encryptedSocket,
                                        Object link) 
      throws GeneralSecurityException, IOException {
      super(null);

      _sender = source.toAddress();
      _link   = link;
      // secret key encrypted by sender or receiver's certificate
      SealedObject senderSecret   = null;
      SealedObject receiverSecret = null;

      Hashtable certTable = keyRing.
        findCertPairFromNS(_sender, target.toAddress());
      _senderCert = (X509Certificate) certTable.get(_sender);
      X509Certificate receiverCert = (X509Certificate) 
          certTable.get(target.toAddress());
      if (_senderCert == null || receiverCert == null) {
        throw new CertificateException("No valid key pair found for the 2 message address " + _sender + " vs "
          + target.toAddress());
      }

      SecretKey secret = null;
      if (log.isDebugEnabled()) {
        log.debug("ProtectedMessageOutputStream: policy = " + policy);
      }
      policy = modifyPolicy(policy, encryptedSocket, link, 
                            _sender, target.toAddress());

      if (log.isDebugEnabled()) {
        log.debug("ProtectedMessageOutputStream: modified policy = " + policy);
      }
      if (policy.secureMethod == policy.ENCRYPT ||
          policy.secureMethod == policy.SIGNENCRYPT) {
        _encrypt = true;
        // first encrypt the secret key with the target's public key
        secret = createSecretKey(policy);
        
        senderSecret = asymmEncrypt(_sender, policy.asymmSpec,
                                    secret, _senderCert);
        receiverSecret = asymmEncrypt(target.toAddress(), policy.asymmSpec,
                                      secret, receiverCert);
      }

      ProtectedMessageHeader header = 
        new ProtectedMessageHeader(_senderCert, receiverCert, policy,
                                   senderSecret, receiverSecret);
      if (log.isDebugEnabled()) {
        log.debug("Sending " + header);
      }
      this.out = (stream instanceof ObjectOutputStream) 
        ? (ObjectOutputStream) stream 
        : new ObjectOutputStream(stream);
      ((ObjectOutputStream) this.out).writeObject(header);

      if (_encrypt) {
        _symmSpec = policy.symmSpec;
        _cipher = getCipher(policy.symmSpec);
        _cipher.init(Cipher.ENCRYPT_MODE, secret);
        this.out = 
          new CipherOutputStream(this.out, getCipher(policy.symmSpec));
      }
      if (policy.secureMethod == policy.SIGNENCRYPT ||
          policy.secureMethod == policy.SIGN) {
        _sign = true;
        PrivateKey priv = getPrivateKey(_sender);
        _signature =  new SignatureOutputStream(this.out, policy.signSpec, 
                                                priv);
        this.out = _signature;
      }
      if (DUMP_MESSAGES) {
        String filename = getDumpFilename();
        if (log.isDebugEnabled()) {
          log.debug("Dumping message content to file " + filename);
        }
        this.out = new DumpOutputStream(this.out, filename);
      }
    }

    public void close() throws IOException {
      if (!_eom) {
        throw new IOException("Buffered data cannot be flushed until end of message");
      }
      super.close();
    }

    /* **********************************************************************
     * ProtectedOutputStream implementation
     */

    public void finishOutput(MessageAttributes attributes)
      throws java.io.IOException {
      this.flush();
      if (DUMP_MESSAGES) {
        ((DumpOutputStream) out).stopDumping();
      }
      if (_sign) {
        _signature.writeSignature();
        setSent(_sender, _link); // verified ok.
      }
      _eom = true;
      if (_encrypt) {
        this.out = null;
        returnCipher(_symmSpec, _cipher);
      }
      log.debug("finishOutputStream from " + _sender);
    }
  }

  private class ProtectedMessageInputStream extends ProtectedInputStream {
    private SignatureInputStream  _signature;
    private boolean               _eom;
    private boolean               _sign;
    private boolean               _encrypt;
    private EventPublisher        _eventPublisher;
    private X509Certificate       _senderCert;
    private Cipher                _cipher;
    private String                _symmSpec;
    private Object                _link;
    private String                _sender;

    public ProtectedMessageInputStream(InputStream stream, 
                                       MessageAddress source,
                                       MessageAddress target,
                                       boolean encryptedSocket,
                                       Object link,
                                       CryptoPolicyService cps) 
      throws GeneralSecurityException, IOException {
      super(null);

      _link = link;

      // first get the header:
      ProtectedMessageHeader header = readHeader(stream);
      String sourceName = header.getSenderName();
      String targetName = header.getReceiverName();
      checkAddresses(sourceName, source, targetName, target);
      keyRing.checkCertificateTrust(header.getSender());
      keyRing.checkCertificateTrust(header.getReceiver());
      _sender = sourceName;

      // check the policy
      Collection policies = 
        cps.getReceivePolicies(sourceName, targetName);

      policies = modifyPolicies(policies, encryptedSocket,
                                link, sourceName, targetName);
      SecureMethodParam headerPolicy = header.getPolicy();

      checkPolicy(policies, headerPolicy, sourceName, targetName);
      if (log.isDebugEnabled()) {
        log.debug("InputStream using policy: " + headerPolicy);
      }

      if (headerPolicy.secureMethod == SecureMethodParam.ENCRYPT ||
          headerPolicy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
        decryptStream(header, targetName);
      }

      if (headerPolicy.secureMethod == SecureMethodParam.SIGNENCRYPT ||
          headerPolicy.secureMethod == SecureMethodParam.SIGN) {
        unsignStream(header);
      }
      if (log.isDebugEnabled()) {
        log.debug("InputStream ready. Reading signed = " + 
                  _sign + ", encrypted = " + _encrypt);
      }
    }

    /* **********************************************************************
     * ProtectedOutputStream implementation
     */

    public void finishInput(MessageAttributes attributes)
      throws java.io.IOException {
      if (_sign) {
        log.debug("trying to verify signature");
        try {
          _signature.verifySignature();
        } catch (SignatureException e) {
          log.debug("Could not verify signature", e);
          throw new IOException(e.getMessage());
        }
        setSent(_sender, _link); // verified ok.
      }
      _eom = true;
      if (_encrypt) {
        returnCipher(_symmSpec, _cipher);
        this.in = null; // so you can't use the Cipher anymore
      }
    }

    private ProtectedMessageHeader readHeader(InputStream stream)
      throws IOException {

      ObjectInputStream ois = (stream instanceof ObjectInputStream) 
        ? (ObjectInputStream) stream
        : new ObjectInputStream(stream);
      this.in = ois;

      try {
        ProtectedMessageHeader header = 
          (ProtectedMessageHeader) ois.readObject();
        if (log.isDebugEnabled()) {
          log.debug("ProtectedMessageInputStream header = " + header);
        }
        return header;
      } catch (ClassNotFoundException e) {
        throw new IOException(e.getMessage());
      }
    }
    
    private void checkAddresses(String sourceName, MessageAddress source,
                                String targetName, MessageAddress target) 
      throws GeneralSecurityException {
      if (!sourceName.equals(source.toAddress()) ||
          !targetName.equals(target.toAddress())) {
        String message = "Break-in attempt: got a message supposedly from " +
          source.toAddress() + " to " + target.toAddress() +
          ", but certificates said " +
          sourceName + " to " + targetName;
        log.warn(message);
        throw new GeneralSecurityException(message);
      }
    }

    private void checkPolicy(Collection policies,
                             SecureMethodParam headerPolicy,
                             String source, String target) 
      throws GeneralSecurityException {
      Iterator iter = policies.iterator();
      boolean headSign = 
        headerPolicy.secureMethod == SecureMethodParam.SIGN ||
        headerPolicy.secureMethod == SecureMethodParam.SIGNENCRYPT;
      boolean headEncrypt = 
        headerPolicy.secureMethod == SecureMethodParam.ENCRYPT ||
        headerPolicy.secureMethod == SecureMethodParam.SIGNENCRYPT;

      while (iter.hasNext()) {
        SecureMethodParam policy = (SecureMethodParam) iter.next();
        boolean sign = policy.secureMethod == policy.SIGN ||
          policy.secureMethod == policy.SIGNENCRYPT;
        boolean encrypt = policy.secureMethod == policy.ENCRYPT ||
          policy.secureMethod == policy.SIGNENCRYPT;

        if (sign && !headSign ||
            encrypt && !headEncrypt) {
          // encryption/sign requirements differ
          continue;
        }
        if ((sign && !policy.signSpec.equals(headerPolicy.signSpec)) ||
            (encrypt && 
             (!policy.asymmSpec.equals(headerPolicy.asymmSpec) ||
              !policy.symmSpec.equals(headerPolicy.symmSpec)))) {
          // encryption/signature specs differ
          continue;
        }
        return; // found one
      }
      String message = "Policy mismatch. Could not find matching policy for " +
        "received message policy " + headerPolicy;
      log.debug(message);
      throw new GeneralSecurityException(message);
    }
    
    private void decryptStream(ProtectedMessageHeader header, 
                               String targetName) 
      throws NoSuchAlgorithmException, InvalidKeyException, 
      NoSuchPaddingException {
      _encrypt = true;
      // first decrypt the secret key with my private key
      X509Certificate receiverCert = header.getReceiver();
      SealedObject encKey = header.getEncryptedSymmetricKey();
      SecureMethodParam policy = header.getPolicy();
      SecretKey secret = (SecretKey) 
        asymmDecrypt(targetName, policy.asymmSpec, encKey);
      _symmSpec = policy.symmSpec;
      _cipher = getCipher(policy.symmSpec);
      _cipher.init(Cipher.DECRYPT_MODE, secret);
      this.in = new CipherInputStream(this.in, _cipher);
    }

    private void unsignStream(ProtectedMessageHeader header) 
      throws CertificateChainException, NoSuchAlgorithmException,
      CertificateExpiredException, InvalidKeyException, 
      CertificateNotYetValidException, CertificateRevokedException {
      _sign = true;
      X509Certificate senderCert = header.getSender();
      keyRing.checkCertificateTrust(senderCert);
      PublicKey pub = senderCert.getPublicKey();
      SecureMethodParam policy = header.getPolicy();
      if (log.isDebugEnabled()) {
        log.debug("unsigning the message using " + policy.signSpec +
                  " and public key " + pub);
      }
      _signature = new SignatureInputStream(this.in, policy.signSpec, pub);
      this.in = _signature;
    }
                     
    public void close() throws IOException {
      if (!_eom) {
        log.error("can't close");
        throw new IOException("Buffered data cannot be flushed until end of message");
      }
      this.in.close();
    }

    /* this was only for debugging... 
    public int available() throws IOException {
      try {
        return this.in.available();
      } catch (Exception e) {
        log.debug("available: ", e);
        return 0;
      }
    }

    public boolean markSupported() {
      try {
        return this.in.markSupported();
      } catch (Exception e) {
        log.debug("markSupported: ", e);
        return false;
      }
    }

    public void mark(int readlimit) {
      try {
        this.in.mark(readlimit);
      } catch (Exception e) {
        log.debug("mark: ", e);
      }
    }

    public long skip(long n) throws IOException {
      try {
        return this.in.skip(n);
      } catch (Exception e) {
        log.debug("skip: ", e);
        return 0;
      }
    }

    public void reset() throws IOException {
      try {
        this.in.reset();
      } catch (Exception e) {
        log.debug("reset: ", e);
      }
    }
    
    public int read() {
      try {
        return this.in.read();
      } catch (Exception e) {
        log.debug("shouldn't be here", e);
        return -1;
      }
    }

    public int read(byte[] b) throws IOException {
      try {
        return this.in.read(b);
      } catch (Exception e) {
        log.debug("read: ", e);
        return -1;
      }
    }

    public int read(byte[] b, int off, int len) throws IOException {
      try {
        return this.in.read(b, off, len);
      } catch (Exception e) {
        log.debug("read: ", e);
        return -1;
      }
    }
    */
  }
}
