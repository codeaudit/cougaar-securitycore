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

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.service.LoggingService;

import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;


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
  private LoggingService log;

  public CryptographicMessage()
  {
   secProvider = new SecurityServiceProvider();
   ServiceBroker sb = secProvider.getServiceBroker();
   keyRing = (KeyRingService)sb.getService(this, KeyRingService.class,
					   null);
   log = (LoggingService)
     sb.getService(this, LoggingService.class, null);
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
      if (log.isDebugEnabled()) {
	log.debug("Error: Signer's certificate not provided");
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
    AlgorithmId signerSignatureAlgorithmId = null;
    try {
      signerDigestAlgorithmId = AlgorithmId.get(sz_digestAlgorithm);
      AlgorithmId.get(sz_privateKeyAlgorithm);
      signerSignatureAlgorithmId = AlgorithmId.get(sz_signatureAlgorithm);
    }
    catch (java.security.NoSuchAlgorithmException e) {
      log.debug("Error: no such algorithm. " + e);
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
      log.debug("Error: " + e);
      return null;
    }
    catch (java.security.InvalidKeyException e) {
      log.debug("Error: " + e);
      return null;
    }
    catch (java.security.SignatureException e) {
      log.debug("Error: " + e);
      return null;
    }

    // Initialize the signer info (PKCS#7 CMS)
    // TODO: should it be subject DN or issuer DN?
    X500Name signerName = (X500Name)signerCertificate.getSubjectDN();
    java.math.BigInteger signerSerialNumber = signerCertificate.getSerialNumber();

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
    if (log.isDebugEnabled()) {
      log.debug("PKCS#7: " + pkcs7);
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
      log.debug("Exception: " + e);
    }
  }

  /** Test code only. */
  public static void main(String[] args) {
    CryptographicMessage m = new CryptographicMessage();
    m.testCryptographicMessage(args);
  }
}
