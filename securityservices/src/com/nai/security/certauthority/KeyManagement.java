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

package com.nai.security.certauthority;

import java.io.*;
import java.net.*;
import java.util.*;
import java.security.cert.*;
import java.security.SignatureException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.PublicKey;
import sun.security.pkcs.*;
import sun.security.x509.*;
import sun.security.util.*;

import com.nai.security.policy.*;
import com.nai.security.crypto.*;

public class KeyManagement
{
  private static boolean debug = true;
  private static final String PKCS10HEADER  = "-----BEGIN NEW CERTIFICATE REQUEST-----";
  private static final String PKCS10TRAILER = "-----END NEW CERTIFICATE REQUEST-----";

  private ConfParser confParser;

  public KeyManagement() {
    confParser = new ConfParser();
  }

  public void signCertificate(byte request[]) {
  }

  public static void main(String[] args) {
    BufferedReader pkcs10stream = null;
    String pkcs10filename = args[0];
    PKCS10 pkcs10Request = null;
    PrintStream dbgout = new PrintStream(System.out);
    String CAsigner = "bootstrapper";
    KeyManagement km = new KeyManagement();

    ArrayList pkcs7Certificates = new ArrayList();
    try {
      ArrayList pkcs10req = km.getSigningRequest(pkcs10filename);
      for (int i = 0 ; i < pkcs10req.size() ; i++) {
	pkcs7Certificates.add(km.signX509Certificate((PKCS10)pkcs10req.get(i), CAsigner));
      }
    }
    catch (Exception e) {
      System.out.println("Exception: " + e);
      e.printStackTrace();
    }
  }
  public ArrayList getSigningRequest(String filename)
    throws FileNotFoundException, IOException, SignatureException,
	   NoSuchAlgorithmException, InvalidKeyException
  {
    if (debug) {
      System.out.println("PKCS10 file: " + filename);
    }
    BufferedReader is = new BufferedReader(new FileReader(filename));
    return getSigningRequest(is);
  }

  /**
   * Get an array of PKCS10 certificate signing requests.
   * The file contains Base64 encoded signing requests, which are each bounded at
   * the beginning by -----BEGIN NEW CERTIFICATE REQUEST-----, and bounded at the
   * end by -----END NEW CERTIFICATE REQUEST-----.
   */
  public ArrayList getSigningRequest(BufferedReader bufreader)
    throws FileNotFoundException, IOException, SignatureException,
	   NoSuchAlgorithmException, InvalidKeyException
  {
    int len = 200;     // Size of a read operation
    int ind_start, ind_stop;
    char [] cbuf = new char[len];
    String sbuf = null;
    ArrayList pkcs10requests = new ArrayList();

    while (bufreader.ready()) {
      bufreader.read(cbuf, 0, len);
      sbuf = sbuf + new String(cbuf);

      // Find header
      ind_start = sbuf.indexOf(PKCS10HEADER);
      if (ind_start == -1) {
	// No header was found
	break;
      }

      // Find trailer
      ind_stop = sbuf.indexOf(PKCS10TRAILER, ind_start);
      if (ind_stop == -1) {
	// No trailer was found. Maybe we didn't read enough data?
	// Try to read more data.
	continue;
      }

      // Extract Base-64 encoded request and remove request from sbuf
      String base64pkcs = sbuf.substring(ind_start + PKCS10HEADER.length(), ind_stop);
      sbuf = sbuf.substring(ind_stop + PKCS10TRAILER.length());
      if (debug) {
	System.out.println("base64pkcs: " + base64pkcs);
      }

      // Decode request and store it as a DER value
      byte pkcs10DER[] = Base64.decode(base64pkcs.toCharArray());
      if (debug) {
	System.out.println("PKCS10 Request:" + new String(Base64.encode(pkcs10DER)));
      }

      // Create PKCS10 object
      PKCS10 pkcs10 = getSigningRequest(pkcs10DER);
      pkcs10requests.add(pkcs10);
    }

    return pkcs10requests;
  }

  /**
   * Get a PKS10 object from a DER encoded certificate signing request.
   */
  public PKCS10 getSigningRequest(byte[] bytes)
    throws IOException, SignatureException, NoSuchAlgorithmException,
	   InvalidKeyException
  {
    PKCS10 request = new PKCS10(bytes);
    
    if (debug) {
      System.out.println("PKCS10 request:" + request.toString());
      // pkcs10Request.print(dbgout);
    }
    return request;
  }

  public int getNextSerialNumber()
  {
    return 1;
  }

  /** Sign a PKCS10 certificate signing request with a CA key
   */
  public PKCS7 signX509Certificate(PKCS10 clientRequest, String caAlias)
    throws IOException, CertificateEncodingException, NoSuchAlgorithmException,
	   CertificateException, SignatureException, InvalidKeyException,
	   NoSuchProviderException
  {
    PKCS7 pkcs7Certificate = null;  // The signed certificate

    // Get CA policy
    CaPolicy caPolicy = null;
    try {
      caPolicy = confParser.readCaPolicy(caAlias);
    }
    catch (Exception e) {
      System.out.println("Unable to read policy" + e);
      e.printStackTrace();
      return pkcs7Certificate;
    }

    // Get X500 name of Certificate authority
    SignerInfo si = null;
    X509Certificate caX509cert = (X509Certificate) KeyRing.getCert(caAlias);
    if (debug) {
      System.out.println("CA x509:" + caX509cert.toString());
    }
    X500Name caX500IssuerName = new X500Name(caX509cert.getSubjectDN().toString()); 

    if (debug) {
      //System.out.println("x500: " + caX500IssuerName.getCommonName());
    }

    // Get Signature object for certificate authority
    PrivateKey caPrivateKey = KeyRing.getPrivateKey(caAlias);
    Signature caSignature = Signature.getInstance(caPrivateKey.getAlgorithm());
    // caSignature.initSign(caPrivateKey);

    X500Signer caX500signer = new X500Signer(caSignature, caX500IssuerName);
    if (debug) {
      System.out.println("Signer: " + caX500signer);
    }

    /** 
     * Client certificate attributes
     * Valid attributes:
     *  version, serialNumber, algorithmID, issuer, validity, subject, key
     *  issuerID, subjectID, extensions
     */
    X509CertInfo clientCertInfo = new X509CertInfo();

    // Set certificate parameters

    // Set version number
    CertificateVersion certversion = new CertificateVersion(caPolicy.certVersion);
    clientCertInfo.set("version", certversion);

    // Set serial number
    CertificateSerialNumber certSerialNumber = new CertificateSerialNumber(getNextSerialNumber());
    clientCertInfo.set("serialNumber", certSerialNumber);

    // Set algorithm ID
    CertificateAlgorithmId certAlgorithmId =
      new CertificateAlgorithmId(caPolicy.algorithmId);
    clientCertInfo.set("algorithmID", certAlgorithmId);

    // Set issuer
    CertificateIssuerName certIssuerName = new CertificateIssuerName(caX500IssuerName);
    clientCertInfo.set("issuer", certIssuerName);

    // Set validity
    // Certificate can be used right away
    Date date_notbefore = new Date();
    // Certificate is valid for a number of days
    Calendar cal_end = Calendar.getInstance();
    cal_end.add(Calendar.DATE, caPolicy.howLong);
    Date date_notafter = cal_end.getTime();
    CertificateValidity certValidity = new CertificateValidity(date_notbefore, date_notafter);
    clientCertInfo.set("validity", certValidity);


    X500Name clientX500Name = clientRequest.getSubjectName();

    // Set subject name
    CertificateSubjectName certSubjectName = new CertificateSubjectName(clientX500Name);
    clientCertInfo.set("subject", certSubjectName);


    // Set client certificate
    CertificateX509Key clientCertificateX509Key =
      new CertificateX509Key(clientRequest.getSubjectPublicKeyInfo());
    X509CertImpl clientCertificate = new X509CertImpl(clientCertInfo);
    clientCertInfo.set("key", clientCertificateX509Key);

    // Set subject unique ID
    /*
    CertificateSubjectUniqueIdentity certSubjectUniqueIdentity = new CertificateSubjectUniqueIdentity();
    clientCertInfo.set("subjectuniqueid", certSubjectUniqueIdentity);
    */
    
    // Set extensions
    //CertificateExtensions


    // Sign certificate
    if (debug) {
      System.out.println("Before signing: " + clientCertificate.toString());
    }
    clientCertificate.sign(caPrivateKey, caPolicy.algorithmId.getName());
    if (debug) {
      System.out.println("After signing: " + clientCertificate.toString());
    }

    // Create the PKCS7 request
    pkcs7Certificate = new PKCS7(clientCertificate.getEncoded());

    if (debug) {
      System.out.println("PKCS7:" + pkcs7Certificate.toString());
    }

    return pkcs7Certificate;
   }

  public void buildPKCS7() {
    AlgorithmId[] digestAlgorithmIds;
    ContentInfo contentInfo;
    X509Certificate[] x509certificate;
    SignerInfo[] asignerinfo;

    /*
    x509certificate[0] = clientCertificate;
    digestAlgorithmIds[0] = caPolicy.algorithmId;
    pkcs7Certificate = new PKCS7();
    clientCertificate.getEncoded();

    String s = privatekey.getAlgorithm();
    String s1;
    if(s.equalsIgnoreCase("DSA"))
      s1 = "SHA1";
    else
      if(s.equalsIgnoreCase("RSA"))
	s1 = "MD5";
      else
	throw new RuntimeException("private key is not a DSA or RSA key");
    String s2 = s1 + "with" + s;
    AlgorithmId algorithmid = AlgorithmId.get(s1);
    AlgorithmId algorithmid1 = AlgorithmId.get(s2);
    AlgorithmId algorithmid2 = AlgorithmId.get(s);
    */
  }

  /** Read a file with Base64 encoded certificates, which are each bounded at
   * the beginning by -----BEGIN CERTIFICATE-----, and bounded at the end by
   * -----END CERTIFICATE-----.
   * We convert the FileInputStream (which does not support mark and reset)
   * to a ByteArrayInputStream (which supports those methods), so that each
   * call to generateCertificate consumes only one certificate, and the read
   * position of the input stream is positioned to the next certificate in the file.
   */
  public ArrayList readX509Certificates(String filename) 
    throws FileNotFoundException, CertificateException, IOException
  {
    FileInputStream fis = new FileInputStream(filename);
    DataInputStream dis = new DataInputStream(fis);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    
    byte[] bytes = new byte[dis.available()];
    dis.readFully(bytes);
    ArrayList certs = new ArrayList();
    ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
    
    while (bais.available() > 0) {
      Certificate cert = cf.generateCertificate(bais);
      certs.add(cert);
      if (debug) {
	System.out.println(cert.toString());
      }
    }
    return certs;
  }

  /** Parse a PKCS#7-formatted certificate reply stored in a file and
   * extracts all the certificates from it.
   */
  public ArrayList parsePkcs7Certificate(String filename)
    throws FileNotFoundException, CertificateException, IOException
  {
    FileInputStream fis = new FileInputStream(filename);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    Collection c = cf.generateCertificates(fis);
    Iterator i = c.iterator();
    ArrayList certs = new ArrayList();
    while (i.hasNext()) {
      Certificate cert = (Certificate)i.next();
      certs.add(cert);
      if (debug) {
	System.out.println(cert);
      }
    }
    return certs;
  }
}


