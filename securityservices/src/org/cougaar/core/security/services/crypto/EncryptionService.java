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


package org.cougaar.core.security.services.crypto;

import java.io.Serializable;
import java.security.SignedObject;
import java.security.cert.CertificateException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

// Cougaar core services
import org.cougaar.core.component.Service;
import com.nai.security.crypto.SecureMethodParam;

/** Service for most common public key cryptographic operations.
 *  Use: cryptographic aspect.
 */
public interface EncryptionService extends Service {

  /** Sign an object.
   *
   *  @param signerName  the common name of the signer. Should be the
   *  name of an agent.
   *  @param signAlgSpec the signature algorithm specification.
   *  @param object      the object to be signed.
   *  @return a signed object.
   */
  public SignedObject sign(String signerName,
			   String signAlgSpec,
			   Serializable object)
    throws RuntimeException, CertificateException;
  
  /** Verify the signature of a signed object.
   *
   *  @param signerName   the common name of the signer. Should be the
   *  name of an agent.
   *  @param signAlgSpec  the signature algorithm specification.
   *  @param signedObject the signed object.
   *  @return the object if the signature is valid.
   */
  public Object verify(String signerName,
		       String signAlgSpec,
		       SignedObject signedObject)
    throws CertificateException;

  /** Encrypt an object using public-key encryption.
   *
   *  @param targetName    the common name of the agent to which this
   *  object is sent. Note that an agent may encrypt an object for
   *  later retrieval by itself, in which case the targetName is the
   *  agent itself.
   *  @param cipherAlgSpec the cipher algorithm specification used
   *  for this operation.
   *  @param object        the object to be encrypted.
   *  @return the encrypted object
   */
  public SealedObject asymmEncrypt(String targetName,
				   String cipherAlgSpec,
				   Serializable object)
    throws RuntimeException,
	   CertificateException,
	   java.security.NoSuchAlgorithmException,
	   java.security.InvalidKeyException,
	   java.io.IOException,
	   javax.crypto.NoSuchPaddingException,
	   javax.crypto.IllegalBlockSizeException;

  /** Decrypt an encrypted object using public-key encryption.
   *
   *  @param targetName    the common name of the agent to which this
   *  object is sent. Note that an agent may encrypt an object for
   *  later retrieval by itself, in which case the targetName is the
   *  agent itself.
   *  @param cipherAlgSpec the cipher algorithm specification used
   *  for this operation.
   *  @param sealedObject  the encrypted object.
   *  @return the decrypted object
   */
  public Object asymmDecrypt(String targetName,
			     String cipherAlgSpec,
			     SealedObject sealedObject)
    throws CertificateException;
  
  /** Encrypt a message using secret key encryption.
   *
   *  @param secretKey     the secret key used to encrypt the object.
   *  @param cipherAlgSpec the cipher algorithm specification used
   *  for this operation.
   *  @param object        the object to be encrypted.
   *  @return the encrypted object
   */
  public SealedObject symmEncrypt(SecretKey secretKey,
				  String cipherAlgSpec,
				  Serializable object)
    throws RuntimeException,
	   CertificateException,
	   java.security.NoSuchAlgorithmException,
	   java.security.InvalidKeyException,
	   java.io.IOException,
	   javax.crypto.NoSuchPaddingException,
	   javax.crypto.IllegalBlockSizeException;

  /** Decrypt an encrypted object using secret key encryption.
   *
   *  @param secretKey     the secret key used to encrypt the object.
   *  @param sealedObject  the encrypted object.
   *  @return the decrypted object
   */
  public Object symmDecrypt(SecretKey secretKey,
			    SealedObject sealedObject);


  public SealedObject signAndEncrypt(Serializable object,
				     String sourceAgent,
				     String targetAgent,
				     SecureMethodParam policy);

  public Object decryptAndVerify(SealedObject object);
}

