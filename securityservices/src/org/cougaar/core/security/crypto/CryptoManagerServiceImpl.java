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
import java.security.*;
import java.util.HashMap;
import java.util.List;
import java.util.Iterator;
import java.security.cert.CertificateException;
import javax.crypto.*;
import java.security.cert.X509Certificate;

// Cougaar core infrastructure
import org.cougaar.core.component.ServiceRevokedListener;
import org.cougaar.core.component.ServiceRevokedEvent;

// Cougaar Security Services
import org.cougaar.core.security.bootstrap.BaseBootstrapper;
import org.cougaar.core.security.util.CryptoDebug;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.crypto.PublicKeyEnvelope;
import org.cougaar.core.security.crypto.SecureMethodParam;

public class CryptoManagerServiceImpl
  implements EncryptionService
{
  private boolean debug = false;
  private KeyRingService keyRing = null;

  public CryptoManagerServiceImpl(KeyRingService aKeyRing) {
    keyRing = aKeyRing;
  }

  public SignedObject sign(final String name,
			   String spec,
			   Serializable obj){
    try {
      List pkList = (List)
	AccessController.doPrivileged(new PrivilegedAction() {
	    public Object run(){
	      return keyRing.findPrivateKey(name);
	    }
	  });
      if (pkList.size() == 0) {
        throw new SecurityException("Private key not found.");
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
    } catch (Exception e) {
      e.printStackTrace();
      BaseBootstrapper.printProviderProperties();
      throw new RuntimeException(e.toString());
    }
  }

  public Object verify(String name, String spec, SignedObject obj)
    throws CertificateException {
    List certList = keyRing.findCert(name);
    if (certList == null || certList.size() == 0) {
      throw
	new CertificateException("Verify. Unable to get certificate for "
				 + name);
    }
    Iterator it = certList.iterator();
    while (it.hasNext()) {
      try {
	java.security.cert.Certificate c = 
	  ((CertificateStatus)it.next()).getCertificate();
	PublicKey pk = c.getPublicKey();
	Signature ve;
	//if(spec==null||spec=="")spec=pk.getAlgorithm();
	spec = AlgorithmParam.getSigningAlgorithm(pk.getAlgorithm());
	ve=Signature.getInstance(spec);
	if (obj.verify(pk,ve)) {
	  return obj.getObject();
	} else {
	  continue;
	}
      } catch (Exception e) {
	e.printStackTrace();
	continue;
      }
    }
    return null;
  }

  public SealedObject asymmEncrypt(String name, String spec, Serializable obj)
    throws CertificateException {
    /*encrypt the secretekey with receiver's public key*/

    List certList = keyRing.findCert(name);
    if (certList.size() == 0) {
      throw new CertificateException("asymmEncrypt. Unable to get certificate for " + name);
    }
    java.security.cert.Certificate cert =
      ((CertificateStatus)certList.get(0)).getCertificate();
    try{
      PublicKey key = cert.getPublicKey();
      if (spec==""||spec==null) spec=key.getAlgorithm();
      if (CryptoDebug.debug) {
	System.out.println("Encrypting for " + name + " using " + spec);
      }
      /*init the cipher*/
      Cipher ci;
      ci=Cipher.getInstance(spec);
      ci.init(Cipher.ENCRYPT_MODE,key);
      return new SealedObject(obj,ci);
    }
    catch(Exception e){
      e.printStackTrace();
      throw new RuntimeException(e.toString());
    }
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
    Iterator it = keyList.iterator();
    PrivateKey key = null;
    Cipher ci = null;
    while (it.hasNext()) {
      key = ((PrivateKeyCert)it.next()).getPrivateKey();
      if(spec==null||spec=="") 
	spec=key.getAlgorithm();
      try {
	ci=Cipher.getInstance(spec);
	ci.init(Cipher.DECRYPT_MODE, key);
	return obj.getObject(ci);
      }
      catch (Exception e) {
	if (CryptoDebug.debug) {
	  System.out.println("Warning: cannot recover message. " + e);
	  e.printStackTrace();
	}
	continue;
      }
    }
    return null;

 
  }

  public SealedObject symmEncrypt(SecretKey sk,
				  String spec,
				  Serializable obj){
    try{
      /*create the cipher and init it with the secret key*/
      Cipher ci;
      ci=Cipher.getInstance(spec);
      ci.init(Cipher.ENCRYPT_MODE,sk);
      return new SealedObject(obj,ci);
    }
    catch(Exception e){
      if (CryptoDebug.debug) {
	System.out.println("ERROR:" + obj.getClass().getName() 
			   + " - " + e);
	e.printStackTrace();
      }
      throw new RuntimeException(e.toString());
    }
  }

  public Object symmDecrypt(SecretKey sk, SealedObject obj){
      Object o = null;
      if (sk == null) {
	if (CryptoDebug.debug) {
	  System.out.println("Secret key not provided!");
	}
	return o;
      }

      try{
	return obj.getObject(sk);
      }
      catch(NullPointerException nullexp){
	boolean loop = true;
	if (CryptoDebug.debug) {
	  System.out.println("in symmDecrypt" +nullexp);
	}
	while(loop){
	  try{
	    Thread.sleep(200);
	    o = obj.getObject(sk);
	    if (debug) {
	      System.out.println("Workaround to Cougaar core bug. Succeeded");
	    }
	    return o;
	  }
	  catch(NullPointerException null1exp){
	    if (CryptoDebug.debug) {
	      System.err.println(
				 "Workaround to Cougaar core bug (Context not known). Sleeping 200ms then retrying...");
	    }
	    //null1exp.printStackTrace();
	    continue;
	  }
	  catch(Exception exp1){
	    exp1.printStackTrace();
	    continue;
	  }
	}
	return null;
      }
      catch(Exception e){
	e.printStackTrace();
	return null;
      }
    }

  public PublicKeyEnvelope signAndEncrypt(Serializable object,
					  String source,
					  String target,
					  SecureMethodParam policy) {
    PublicKeyEnvelope envelope = null;

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

    /* Generate the secret key */
    int i = policy.symmSpec.indexOf("/");
    String a;
    a =  i > 0 ? policy.symmSpec.substring(0,i) : policy.symmSpec;
    if(debug) {
      System.out.println("Secret Key Parameters: " + a);
    }
    SecureRandom random = new SecureRandom();
    try {
      KeyGenerator kg=KeyGenerator.getInstance(a);
      kg.init(random);
      SecretKey sk=kg.generateKey();

      SealedObject sessionKey = null;
      SealedObject sealedObject = null;
      SignedObject signedObject = null;
      
      // Encrypt session key
      sessionKey = asymmEncrypt(target, policy.asymmSpec, sk);

      // Sign object
      signedObject = sign(source, policy.signSpec, object);

      // Encrypt object
      sealedObject = symmEncrypt(sk, policy.symmSpec, signedObject);
      
      // Find source certificate
      List senderList = keyRing.findCert(source);
      if (senderList.size() == 0) {
	throw new RuntimeException("Unable to find sender certificate: " 
				   + source);
      }
      X509Certificate sender = ((CertificateStatus)senderList.get(0)).getCertificate();

      List receiverList = keyRing.findCert(target);
      if (receiverList.size() == 0) {
	throw new RuntimeException("Unable to find target certificate: " 
				   + target);
      }
      X509Certificate receiver = ((CertificateStatus)receiverList.get(0)).getCertificate();

      envelope = 
	new PublicKeyEnvelope(sender, receiver, sessionKey, sealedObject);
    }
    catch (java.security.NoSuchAlgorithmException e) {
      throw new RuntimeException("Unable to protect object: " + e);
    }
    catch (java.security.cert.CertificateException e) {
      throw new RuntimeException("Unable to protect object: " + e);
    }
    return envelope;
  }

  public Object decryptAndVerify(String source,
				 String target,
				 PublicKeyEnvelope envelope,
				 SecureMethodParam policy) {
    // Retrieving the secret key, which was encrypted using the public key
    // of the target.
    SecretKey sk=(SecretKey)
      asymmDecrypt(target, policy.asymmSpec,
		   envelope.getEncryptedSymmetricKey());
    if (sk == null) {
      if (debug) {
	System.out.println("Error: unable to retrieve secret key");
      }
      return null;
    }

    // Decrypt the object
    SignedObject signedObject =
      (SignedObject)symmDecrypt(sk, envelope.getEncryptedObject());

    // Verify the signature
    Object o = null;
    try {
      o = verify(source, policy.signSpec, signedObject);
    }
    catch (CertificateException e) {
    }
    return o;
  }
}

