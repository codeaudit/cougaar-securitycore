/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */

package org.cougaar.core.security.crypto;

import java.io.*;
import java.util.*;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.Signature;
import java.security.PrivateKey;

import sun.security.pkcs.*;
import sun.security.x509.*;
import sun.security.util.BigInt;

// Cougaar Security Services
import org.cougaar.core.security.util.CryptoDebug;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.provider.SecurityServiceProvider;

/** This class provides support for the Cryptographic Message Syntax (CMS),
    which is defined in RFC 2630. The CMS syntax is used to digitally sign,
    digest, authenticate, or encrypt arbitrary messages.
    The Cryptographic Message Syntax is derived from PKCS #7 version 1.5
    as specified in RFC 2315 [PKCS#7]. Wherever possible, backward
    compatibility is preserved; however, changes were necessary to
    accommodate attribute certificate transfer and key agreement
    techniques for key management.
*/
public class CryptographicMessage
{
  private KeyRingService keyRing = null;
  private SecurityServiceProvider secProvider = null;

  public CryptographicMessage()
  {
   secProvider = new SecurityServiceProvider();
   keyRing = (KeyRingService)secProvider.getService(null,
						    this,
						    KeyRingService.class);
  }

  public PKCS7 encryptData()
  {
    PKCS7 pkcs7 = null;
    return pkcs7;
  }

  /**
   * @param certChain  The signer's certificate and its certificate chain.
   * @param privatekey The private key of the signer.
   * @param message    The message to be protected.
   */
  public PKCS7 signData(X509Certificate signerCertificate,
		       PrivateKey privatekey,
		       byte[] message)
    throws CertificateException
  {
    if (signerCertificate == null) {
      if (CryptoDebug.debug) {
	System.out.println("Error: Signer's certificate not provided");
      }
      throw new CertificateException("Signer's certificate not provided");
    }

    /* digestAlgorithms is a collection of message digest algorithm
     * identifiers.  There may be any number of elements in the
     * collection, including zero.  Each element identifies the message
     * digest algorithm, along with any associated parameters, used by
     * one or more signer.  The collection is intended to list the
     * message digest algorithms employed by all of the signers, in any
     * order, to facilitate one-pass signature verification.
     * The following algorithm ID are supported:
     * MD2, MD5, SHA, SHA1, RSA, Diffie-Hellman, DH, DSA, MD5withRSA,
     * MD2withRSA, SHAwithDSA, DSAWithSHA1.
     */
    AlgorithmId[] digestAlgorithms;

    /* The content info is intended to refer to arbitrary octet
     * strings, such as ASCII text files; the interpretation is left to the
     * application.  Such strings need not have any internal structure
     * (although they could have their own ASN.1 definition or other
     * structure).
     * The data content type is generally encapsulated in the signed-data,
     * enveloped-data, digested-data, encrypted-data, or authenticated-data
     * content type.
     */
    ContentInfo contentinfo;

    /* certificates is a collection of certificates.  It is intended that
     * the set of certificates be sufficient to contain chains from a
     * recognized "root" or "top-level certification authority" to all of
     * the signers in the signerInfos field.  There may be more
     * certificates than necessary, and there may be certificates
     * sufficient to contain chains from two or more independent top-
     * level certification authorities.  There may also be fewer
     * certificates than necessary, if it is expected that recipients
     * have an alternate means of obtaining necessary certificates (e.g.,
     * from a previous set of certificates).
     */
    X509Certificate[] certificates;

    /* signerInfos is a collection of per-signer information.  There may
     * be any number of elements in the collection, including zero.
     * signerInfos contains the following attributes:
     *  - SignerIdentifier:
     *    specifies the signer's certificate (and thereby the signer's
     *    public key).  The signer's public key is needed by the recipient
     *    to verify the signature.  SignerIdentifier provides two
     *    alternatives for specifying the signer's public key.  The
     *    issuerAndSerialNumber alternative identifies the signer's
     *    certificate by the issuer's distinguished name and the certificate
     *    serial number; the subjectKeyIdentifier identifies the signer's
     *    certificate by the X.509 subjectKeyIdentifier extension value.
     *  - digestAlgorithm:
     *    identifies the message digest algorithm, and any
     *    associated parameters, used by the signer.  The message digest is
     *    computed on either the content being signed or the content
     *    together with the signed attributes. The message digest algorithm
     *    should be among those listed in the digestAlgorithms field of the
     *    associated SignerData.
     *  - signatureAlgorithm:
     *    identifies the signature algorithm, and any associated parameters,
     *    used by the signer to generate the digital signature.
     *  - signature:
     *    is the result of digital signature generation, using the
     *    message digest and the signer's private key.
     */
    SignerInfo[] signerInfos;

    // Start with plain text message.
    contentinfo = new ContentInfo(message);

    // The signer's certificate and its certificate chain.
    certificates = keyRing.findCertChain(signerCertificate);

    // Figure out the digest and encryption algorithm.
    String sz_privateKeyAlgorithm = privatekey.getAlgorithm();
    String sz_digestAlgorithm;
    String sz_signatureAlgorithm;
    if(sz_privateKeyAlgorithm.equalsIgnoreCase("DSA")) {
      sz_digestAlgorithm = "SHA1";
    }
    else if(sz_privateKeyAlgorithm.equalsIgnoreCase("RSA")) {
      sz_digestAlgorithm = "MD5";
    }
    else {
      throw new RuntimeException("private key is not a DSA or RSA key");
    }
    sz_signatureAlgorithm = sz_digestAlgorithm + "with"
      + sz_privateKeyAlgorithm;

    AlgorithmId signerDigestAlgorithmId = null;
    AlgorithmId signerCipherAlgorithmId = null;
    AlgorithmId signerSignatureAlgorithmId = null;
    try {
      signerDigestAlgorithmId = AlgorithmId.get(sz_digestAlgorithm);
      signerCipherAlgorithmId = AlgorithmId.get(sz_privateKeyAlgorithm);
      signerSignatureAlgorithmId = AlgorithmId.get(sz_signatureAlgorithm);
    }
    catch (java.security.NoSuchAlgorithmException e) {
      System.out.println("Error: no such algorithm. " + e);
      return null;
    }

    // Sign the data.
    Signature signature = null;
    byte signedMessage[] = null;
    try {
      signature = Signature.getInstance(sz_signatureAlgorithm);
      signature.initSign(privatekey);
      signature.update(message);
      signedMessage = signature.sign();
    }
    catch (java.security.NoSuchAlgorithmException e) {
      System.out.println("Error: " + e);
      return null;
    }
    catch (java.security.InvalidKeyException e) {
      System.out.println("Error: " + e);
      return null;
    }
    catch (java.security.SignatureException e) {
      System.out.println("Error: " + e);
      return null;
    }

    // Initialize the signer info (PKCS#7 CMS)
    // TODO: should it be subject DN or issuer DN?
    X500Name signerName = (X500Name)signerCertificate.getSubjectDN();
    java.math.BigInteger biginteger = signerCertificate.getSerialNumber();
    BigInt signerSerialNumber = new BigInt(biginteger);

    digestAlgorithms = new AlgorithmId[1];
    digestAlgorithms[0] = signerDigestAlgorithmId;

    SignerInfo signerInfo
      = new SignerInfo(signerName, signerSerialNumber,
		       signerDigestAlgorithmId,
		       signerSignatureAlgorithmId,
		       signedMessage);

    signerInfos = new SignerInfo[1];
    signerInfos[0] = signerInfo;

    PKCS7 pkcs7 = new PKCS7(digestAlgorithms, contentinfo,
			    certificates, signerInfos);
    if (CryptoDebug.debug) {
      System.out.println("PKCS#7: " + pkcs7);
    }
    return pkcs7;
  }

  private void testCryptographicMessage(String[] args)
  {
    List signerCertificateList = keyRing.findCert(args[0]);
    X509Certificate signerCertificate =
      ((CertificateStatus)signerCertificateList.get(0)).getCertificate();
    List privatekeyList = keyRing.findPrivateKey(args[0]);
    PrivateKey privatekey = ((PrivateKeyCert)(privatekeyList.get(0))).getPrivateKey();
    String text = "This is a test message";
    byte[] message = text.getBytes();

    try {
      PKCS7 pkcs7 = signData(signerCertificate,
			     privatekey,
			     message);
    }
    catch (Exception e) {
      System.out.println("Exception: " + e);
    }
  }

  /** Test code only. */
  public static void main(String[] args) {
    CryptographicMessage m = new CryptographicMessage();
    m.testCryptographicMessage(args);
  }
}
