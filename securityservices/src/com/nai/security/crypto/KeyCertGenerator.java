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

package com.nai.security.crypto;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import sun.security.pkcs.PKCS10;
import sun.security.x509.*;
import com.nai.security.util.CryptoDebug;

public final class KeyCertGenerator
{
  //private boolean CryptoDebug.debug = false;

  /** Initialize the key pair generator.
   *  @param algorithm      The standard string name of the algorithm.
   *  RSA or DSA.
   *  @param signatureAlg   Used when generating an instance of Signature. 
   *  SHA1withDSA: The DSA with SHA-1 signature algorithm which uses the
   *               SHA-1 digest algorithm and DSA to create and verify DSA
   *               digital signatures as defined in FIPS PUB 186. 
   *  MD2withRSA:  The MD2 with RSA Encryption signature algorithm which
   *               uses the MD2 digest algorithm and RSA to create and
   *               verify RSA digital signatures as defined in PKCS#1. 
   *  MD5withRSA:  The MD5 with RSA Encryption signature algorithm which
   *               uses the MD5 digest algorithm and RSA to create and
   *               verify RSA digital signatures as defined in PKCS#1. 
   *  SHA1withRSA: The signature algorithm with SHA-1 and the RSA encryption
   *               algorithm as defined in the OSI Interoperability Workshop,
   *               using the padding conventions described in PKCS #1.
   * @param provider        A specific provider to use. Set to null if any
   *                        provider is ok.
   */
  public KeyCertGenerator(String algorithm, String signatureAlg,
			  String provider)
    throws NoSuchAlgorithmException, NoSuchProviderException
  {
    if (provider == null || provider.equals("")) {
      keyGen = KeyPairGenerator.getInstance(algorithm);
    }
    else {
      keyGen = KeyPairGenerator.getInstance(algorithm, provider);
    }

    sigAlg = signatureAlg;
  }

  public void setRandom(SecureRandom securerandom)
  {
    prng = securerandom;
  }

  public void generate(int keysize)
    throws InvalidKeyException
  {
    KeyPair keypair;
    try
      {
	if(prng == null)
	  prng = new SecureRandom();
	if (CryptoDebug.debug) {
	  System.out.println("Generate key pair. Using provider: " +
			     keyGen.getProvider().toString());
	}
	keyGen.initialize(keysize, prng);
	keypair = keyGen.generateKeyPair();
      }
    catch(Exception exception)
      {
	throw new IllegalArgumentException(exception.getMessage());
      }
    publicKey = keypair.getPublic();
    privateKey = keypair.getPrivate();
  }

  public PublicKey getPublicKey()
  {
    return publicKey;
  }

  public PrivateKey getPrivateKey()
  {
    return privateKey;
  }

  public X509Certificate getSelfCertificate(X500Name x500name, long l)
    throws CertificateException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException
  {
    try
      {
	X500Signer x500signer = getSigner(x500name);
	Date date = new Date();
	Date date1 = new Date();
	date1.setTime(date1.getTime() + l * 1000L);
	CertificateValidity certificatevalidity = new CertificateValidity(date, date1);
	X509CertInfo x509certinfo = new X509CertInfo();
	x509certinfo.set("version", new CertificateVersion(0));
	x509certinfo.set("serialNumber", new CertificateSerialNumber((int)(date.getTime() / 1000L)));
	AlgorithmId algorithmid = x500signer.getAlgorithmId();
	x509certinfo.set("algorithmID", new CertificateAlgorithmId(algorithmid));
	x509certinfo.set("subject", new CertificateSubjectName(x500name));
	x509certinfo.set("key", new CertificateX509Key(publicKey));
	x509certinfo.set("validity", certificatevalidity);
	x509certinfo.set("issuer", new CertificateIssuerName(x500signer.getSigner()));
	X509CertImpl x509certimpl = new X509CertImpl(x509certinfo);
	x509certimpl.sign(privateKey, sigAlg);
	return x509certimpl;
      }
    catch(IOException ioexception)
      {
	throw new CertificateEncodingException("getSelfCert: " + ioexception.getMessage());
      }
  }

  public PKCS10 getCertRequest(X500Name x500name)
    throws InvalidKeyException, SignatureException
  {
    PKCS10 pkcs10 = new PKCS10(publicKey);
    try
      {
	pkcs10.encodeAndSign(getSigner(x500name));
      }
    catch(CertificateException certificateexception)
      {
	throw new SignatureException(sigAlg + " CertificateException");
      }
    catch(IOException ioexception)
      {
	throw new SignatureException(sigAlg + " IOException");
      }
    catch(NoSuchAlgorithmException nosuchalgorithmexception)
      {
	throw new SignatureException(sigAlg + " unavailable?");
      }
    return pkcs10;
  }

  private X500Signer getSigner(X500Name x500name)
    throws InvalidKeyException, NoSuchAlgorithmException
  {
    Signature signature = Signature.getInstance(sigAlg);
    signature.initSign(privateKey);
    return new X500Signer(signature, x500name);
  }

  private SecureRandom prng;
  private String sigAlg;
  private KeyPairGenerator keyGen;
  private PublicKey publicKey;
  private PrivateKey privateKey;
}
