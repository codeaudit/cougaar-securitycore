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

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import javax.crypto.*;
import java.security.cert.*;

// Cougaar core services
import org.cougaar.core.component.Service;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.ProtectedOutputStream;
import org.cougaar.core.mts.ProtectedInputStream;

// Cougaar security services
import org.cougaar.core.security.crypto.ProtectedObject;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.policy.CryptoPolicy;
import org.cougaar.core.security.policy.enforcers.ULMessageNodeEnforcer;

/** Service for most common public key cryptographic operations.
 *  Use: cryptographic aspect.
 */
public interface EncryptionService extends Service {

  /**
   * Returns whether or not the send needs a signature when encryption
   * is available.
   */
  public boolean sendNeedsSignature(String source, String target);

  /**
   * Returns whether or not a received message needs a signature
   * when the socket is encrypted.
   */
  public boolean receiveNeedsSignature(String source);

  /**
   * Sets that sending a message from the source needs a signature when
   * using SSL.
   */
  public void setSendNeedsSignature(String source, String target);

  /**
   * Sets that sending a message from the source does not need a signature
   * when using SSL.
   */
  public void removeSendNeedsSignature(String source, String target);

  /**
   * Sets that a received message has a valid signature when using
   * SSL.
   */
  public void setReceiveSignatureValid(String source);

  /**
   * Encrypt a secret key with a certificate's public key
   */
  public byte[] encryptSecretKey(String algorithm, SecretKey skey,
                                 X509Certificate cert) 
    throws GeneralSecurityException;

  /**
   * Decrypt a secret key with the secret key for the given certificate
   */
  public SecretKey decryptSecretKey(String publicKeyAlg, byte[] sKeyBytes,
                                    String secretKeyAlg,
                                    X509Certificate cert)
    throws GeneralSecurityException;

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
    throws GeneralSecurityException, IOException;

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

  public Object verify(String signerName,
		       String signAlgSpec,
		       SignedObject signedObject,
                       boolean expiredOk)
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
				   Serializable object,
				   java.security.cert.Certificate cert)
    throws GeneralSecurityException, IOException;

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
    throws GeneralSecurityException, IOException;

  /** Decrypt an encrypted object using secret key encryption.
   *
   *  @param secretKey     the secret key used to encrypt the object.
   *  @param sealedObject  the encrypted object.
   *  @return the decrypted object
   */
  public Object symmDecrypt(SecretKey secretKey,
			    SealedObject sealedObject);


  public ProtectedObject protectObject(Serializable object,
				       MessageAddress sourceAgent,
				       MessageAddress targetAgent,
				       SecureMethodParam policy)
    throws GeneralSecurityException, IOException;

  public Object unprotectObject(MessageAddress source,
				MessageAddress target,
				ProtectedObject envelope,
				SecureMethodParam policy)
    throws GeneralSecurityException;

  public ProtectedObject protectObject(Serializable object,
				       MessageAddress sourceAgent,
				       MessageAddress targetAgent,
				       CryptoPolicy policy)
    throws GeneralSecurityException, IOException;

  public Object unprotectObject(MessageAddress source,
				MessageAddress target,
				ProtectedObject envelope,
				CryptoPolicy policy)
    throws GeneralSecurityException, IOException;

  public Cipher getCipher(String spec)
    throws NoSuchAlgorithmException, NoSuchPaddingException;

  public void returnCipher(String spec, Cipher ci);
}

