/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.crypto;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

import sun.security.pkcs.PKCS10;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.OIDMap;
import sun.security.x509.X500Name;
import sun.security.x509.X500Signer;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;


public final class KeyCertGenerator
{
  //private boolean log.isDebugEnabled() = false;
  private ServiceBroker serviceBroker;
  private LoggingService log;

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
			  String provider, ServiceBroker sb)
    throws NoSuchAlgorithmException, NoSuchProviderException
  {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
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
	if (log.isDebugEnabled()) {
	  log.debug("Generate key pair. Using provider: " +
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

  public X509Certificate getSelfCertificate(X500Name x500name, long envelope, long l, boolean isSigner)
    throws CertificateException, InvalidKeyException, SignatureException,
    NoSuchAlgorithmException, NoSuchProviderException
  {
    try
      {
	X500Signer x500signer = getSigner(x500name);
	Date date = new Date();
	Date date1 = new Date();
        date.setTime(date.getTime() - envelope * 1000L);
	date1.setTime(date1.getTime() + l * 1000L);

	log.debug("date: " + date.toString());
	log.debug("date1: " + date1.toString());
	log.debug("l: " + l);

	CertificateValidity certificatevalidity = new CertificateValidity(date, date1);
	X509CertInfo x509certinfo = new X509CertInfo();
	x509certinfo.set("version", new CertificateVersion(2));
	x509certinfo.set("serialNumber", new CertificateSerialNumber((int)(date.getTime() / 1000L)));
	AlgorithmId algorithmid = x500signer.getAlgorithmId();
	x509certinfo.set("algorithmID", new CertificateAlgorithmId(algorithmid));
	x509certinfo.set("subject", new CertificateSubjectName(x500name));
	x509certinfo.set("key", new CertificateX509Key(publicKey));
	x509certinfo.set("validity", certificatevalidity);
	x509certinfo.set("issuer", new CertificateIssuerName(x500signer.getSigner()));
	X509CertImpl x509certimpl = new X509CertImpl(x509certinfo);

        String s = OIDMap.getName(new ObjectIdentifier("2.5.29.15"));

        if (isSigner) {
          // Set keyusage
          KeyUsageExtension keyusage = new KeyUsageExtension();
          keyusage.set("key_certsign", new Boolean(true));
          if(s != null) {
            x509certimpl.set(s, keyusage);
          }
        }

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
