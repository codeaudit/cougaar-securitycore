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

import java.io.Serializable;
import java.security.*;
import java.util.HashMap;
import java.security.cert.CertificateException;

import org.cougaar.core.security.bootstrap.BaseBootstrapper;
import com.nai.security.util.CryptoDebug;

import javax.crypto.*;

public class CryptoManagerServiceImpl implements CryptoManagerService {
  private boolean debug = false;

  public CryptoManagerServiceImpl() {
    /* debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    */
  }

  public SignedObject sign(final String name, String spec, Serializable obj){
    try {
      PrivateKey pk = (PrivateKey) AccessController.doPrivileged(new PrivilegedAction() {
	  public Object run(){
	    return KeyRing.findPrivateKey(name);
	  }
	  
	});
      Signature se;
      // if(spec==null||spec=="")spec=pk.getAlgorithm();
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
       java.security.cert.Certificate c = KeyRing.findCert(name);
       if (c == null) {
	 throw new CertificateException("Verify. Unable to get certificate for " + name);
       }
       try {
	 PublicKey pk = c.getPublicKey();
	 Signature ve;
	 //if(spec==null||spec=="")spec=pk.getAlgorithm();
	 spec = AlgorithmParam.getSigningAlgorithm(pk.getAlgorithm());
	 ve=Signature.getInstance(spec);
	 if (obj.verify(pk,ve)) {
	   return obj.getObject();
	 } else {
	   return null;
	 }
       } catch (Exception e) {
	 e.printStackTrace();
	 return null;
      }
    }
    
  public SealedObject asymmEncrypt(String name, String spec, Serializable obj)
    throws CertificateException {
    /*encrypt the secretekey with receiver's public key*/

    java.security.cert.Certificate cert = KeyRing.findCert(name);
    if (cert == null) {
      throw new CertificateException("asymmEncrypt. Unable to get certificate for " + name);
    }
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
  
  public Object asymmDecrypt(final String name, String spec, SealedObject obj){
    try{
      /*get secretKey*/
      PrivateKey key = (PrivateKey)
	AccessController.doPrivileged(new PrivilegedAction() {
	    public Object run(){
	      return KeyRing.findPrivateKey(name);
	    }
	  });
      
      if(spec==null||spec=="") spec=key.getAlgorithm(); 
      Cipher ci;
      ci=Cipher.getInstance(spec);
      ci.init(Cipher.DECRYPT_MODE, key);
      return obj.getObject(ci);
    }
    catch(Exception e){
      if (CryptoDebug.debug) {
	System.out.println("Error: cannot recover message. Invalid key?");
	e.printStackTrace();
      }
      return null;
    }
  }
    
    public SealedObject symmEncrypt(SecretKey sk, String spec, Serializable obj){
      try{
          /*create the cipher and init it with the secret key*/
          Cipher ci;
          ci=Cipher.getInstance(spec);
          ci.init(Cipher.ENCRYPT_MODE,sk);
          return new SealedObject(obj,ci);
      }
      catch(Exception e){
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
    
}

