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
import java.security.MessageDigest;

import sun.security.pkcs.*;
import sun.security.x509.*;
import sun.security.util.*;
import sun.security.provider.*;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import org.cougaar.util.ConfigFinder;

import com.nai.security.policy.*;
import com.nai.security.crypto.*;

public class KeyManagement
{
  private static boolean debug = true;
  private static final String PKCS10HEADER  = "-----BEGIN NEW CERTIFICATE REQUEST-----";
  private static final String PKCS10TRAILER = "-----END NEW CERTIFICATE REQUEST-----";

  private static final String PKCS7HEADER   = "-----BEGIN CERTIFICATE-----";
  private static final String PKCS7TRAILER  = "-----END CERTIFICATE-----";
  private String topLevelDirectory = null;
  private String x509directory = null;
  private ConfParser confParser = null;
  private CaPolicy caPolicy = null;            // the policy of the CA
  private DirectoryKeyStore caKeyStore = null; // the keystore where the CA private key is stored
  private String caDN = null;                  // the distinguished name of the CA
  private X509Certificate caX509cert = null;   // the X.509 certificate of the CA
  private X500Name caX500Name = null;          // the X.500 name of the CA

  private String x509DirectoryName;
  private String pkcs10DirectoryName;
  private String confDirectoryName;

  public KeyManagement(String aCA_DN) 
    throws Exception{
    caDN = aCA_DN;
    confParser = new ConfParser();

    try {
      caPolicy = confParser.readCaPolicy(caDN);
    }
    catch (Exception e) {
      throw new Exception("Unable to read policy" + e);
    }
    caX500Name = new X500Name(caDN);

    String caCommonName = caX500Name.getCommonName();
    String certpath = System.getProperty("org.cougaar.security.CA.certpath");
    if (certpath != null) {
      if (debug) {
	System.out.println("Running as standalone CA");
      }

      /* The following directory structure will be created when running as a standalone CA:
       * top-level directory (org.cougaar.security.CA.certpath)
       * +-+ <CA common name>
       *   +-+ conf
       *     +-- <keystore file>
       *     +-- <serial number file>
       *     +-- <pkcs10Directory>
       *     +-- <x509CertDirectory>
       */
      String topLevelDirectory = certpath + File.separatorChar + caCommonName;
      confDirectoryName = topLevelDirectory +  File.separatorChar + "conf";
    }
    else {
      if (debug) {
	System.out.println("Running in Cougaar environment");
      }
      /* When running as part of Cougaar, the KeyRing class is used to store the
       * private keys and the certificates.
       */
      ConfigFinder configFinder = new ConfigFinder();
      File f = configFinder.locateFile(caPolicy.keyStoreFile);
      if (f == null) {
	throw new FileNotFoundException("Unable to locate CA keystore file");
      }
      confDirectoryName = f.getPath();
    }

    x509DirectoryName =  confDirectoryName + File.separatorChar + caPolicy.x509CertDirectory;
    pkcs10DirectoryName = confDirectoryName +  File.separatorChar + caPolicy.pkcs10Directory;

    // Create directory structure if it hasn't been created yet.
    createDirectoryStructure();

    // Open keystore file
    // TODO
    String keystoreFile = confDirectoryName + File.separatorChar + caPolicy.keyStoreFile;
    if (debug) {
      System.out.println("CA keystore: " + keystoreFile);
    }
    FileInputStream f = new FileInputStream(keystoreFile);
    caKeyStore = new DirectoryKeyStore(f, caPolicy.keyStorePassword.toCharArray(), null, null);

    // Get CA X.509 certificate
    // TODO
    caX509cert = (X509Certificate) caKeyStore.getCert(caPolicy.alias);

  }

  private void createDirectoryStructure()
    throws IOException
  {
    File pkcs10dir = new File(pkcs10DirectoryName);
    pkcs10dir.mkdirs();

    File x509dir = new File(x509DirectoryName);
    x509dir.mkdirs();

    File confdir = new File(confDirectoryName);
    confdir.mkdirs();
  }

  public void processX509Request(PrintStream out, InputStream inputstream) {
    Collection c = null;
    if(inputstream == null)
      return;
    try {
      // Extract X509 certificates from the input stream
      if(!inputstream.markSupported()) {
	byte abyte0[] = getTotalBytes(new BufferedInputStream(inputstream));
	inputstream = new ByteArrayInputStream(abyte0);
      }
      if(isBase64(inputstream)) {
	byte abyte1[] = base64_to_binary(inputstream);
	c = parseX509orPKCS7Cert(new ByteArrayInputStream(abyte1));
      } else {
	c = parseX509orPKCS7Cert(inputstream);
      }

      Iterator i = c.iterator();
      while (i.hasNext()) {
	X509CertImpl clientX509 = (X509CertImpl) i.next();
	// Lookup certificate using DirectoryKeyStore

	// Save the X509 reply in a file
	saveX509Request(clientX509);

	// Publish certificate in LDAP directory
	publish2Ldap(clientX509);
      }
    }
    catch(Exception e) {
      System.out.println("Unable to process request: " + e);
      e.printStackTrace();
    }
  }

  public X509Certificate[] processPkcs10Request(InputStream request) {
    ArrayList ar = new ArrayList();
    try {
      // First, get all the PKCS10 requests in an array list.
      ArrayList requests = getSigningRequests(request);

      // Loop through each request and sign it.
      Iterator i = requests.iterator();
      while (i.hasNext()) {
	PKCS10 req = (PKCS10)i.next();

	X509CertImpl clientX509 = signX509Certificate(req);
	ar.add(clientX509);
	// Save the X509 reply in a file
	saveX509Request(clientX509);

	// Publish certificate in LDAP directory
	publish2Ldap(clientX509);
      }
    }
    catch (Exception e) {
      System.out.println("Unable to process request: " + e);
      e.printStackTrace();
    }

    X509Certificate[] reply = new X509Certificate[ar.size()];
    for (int i = 0 ; i < ar.size() ; i++) {
      reply[i] = (X509Certificate)ar.get(i);
    }
    return reply;
  }

  public void processPkcs10Request(PrintStream out, InputStream request)
    throws CertificateEncodingException, IOException
  {
    X509Certificate[] certs = processPkcs10Request(request);
    base64EncodeCertificates(out, certs);
  }

  public void base64EncodeCertificates(PrintStream out, X509Certificate[] certs)
    throws CertificateEncodingException, IOException
  {
    for (int i = 0 ; i < certs.length ; i++) {
      base64encode(out, certs[i].getEncoded(), PKCS7HEADER, PKCS7TRAILER);
    }
  }

  private void base64encode(PrintStream out, byte [] der, String header, String trailer)
    throws IOException
  {
    out.println(header);
    BASE64Encoder b64 = new BASE64Encoder();
    b64.encodeBuffer(der, out);
    out.println(trailer);
  }

  private void saveX509Request(X509CertImpl clientX509)
    throws IOException, CertificateEncodingException, NoSuchAlgorithmException
  {
    String alias = caKeyStore.getAlias(clientX509);
    File f = new File(x509DirectoryName + File.separatorChar + alias);
    f.createNewFile();
    PrintStream out = new PrintStream(new FileOutputStream(f));
    base64encode(out, clientX509.getEncoded(), PKCS7HEADER, PKCS7TRAILER);

    out.close();
  }

  private void publish2Ldap(X509Certificate clientX509)
    throws IOException
  {
    X500Name clientX500Name = new X500Name(clientX509.getSubjectDN().toString()); 
  }

  public void printPkcs7Request(String filename)
  {
    try {
      FileInputStream is = new FileInputStream(filename);
      X509Factory x509factory = new X509Factory();
      Collection c = x509factory.engineGenerateCertificates(is);
      System.out.println(c);
      //BufferedReader is = new BufferedReader(new FileReader(filename));
      //printPkcs7Request(is);
   }
    catch (Exception e) {
      System.out.println("Exception: " + e);
      e.printStackTrace();
    }
  }

  public Collection printPkcs7Request(InputStream inputstream)
    throws CertificateException
  {
    if(inputstream == null)
      throw new CertificateException("Missing input stream");
    try {
      if(!inputstream.markSupported()) {
	byte abyte0[] = getTotalBytes(new BufferedInputStream(inputstream));
	inputstream = new ByteArrayInputStream(abyte0);
      }
      if(isBase64(inputstream)) {
	byte abyte1[] = base64_to_binary(inputstream);
	return parseX509orPKCS7Cert(new ByteArrayInputStream(abyte1));
      } else {
	return parseX509orPKCS7Cert(inputstream);
      }
    }
    catch(IOException ioexception) {
      throw new CertificateException(ioexception.getMessage());
    }
  }
  
  public void printPkcs7Request(BufferedReader bufreader)
  {
    try {
      int len = 2000;     // Size of a read operation
      char [] cbuf = new char[len];
      String sbuf = null;
      while (bufreader.ready()) {
	int read = bufreader.read(cbuf, 0, len);
	sbuf = sbuf + new String(cbuf, 0, read);
      }
      String base64EncodeRequest = getBase64Block(sbuf, PKCS7HEADER, PKCS7TRAILER);
      byte der[] = Base64.decode(base64EncodeRequest.toCharArray());
      InputStream inputstream = new ByteArrayInputStream(der);
      PKCS7 pkcs7 = new PKCS7(inputstream);
      System.out.println("PKCS7: " + pkcs7);
    }
    catch (Exception e) {
      System.out.println("Exception: " + e);
      e.printStackTrace();
    }
  }

  private String getBase64Block(String sbuf, String header, String trailer)
    throws Base64Exception
  {
    int ind_start, ind_stop;

    // Find header
    ind_start = sbuf.indexOf(header);
    if (ind_start == -1) {
      // No header was found
      throw new Base64Exception("No Header", Base64Exception.NO_HEADER_EXCEPTION);
    }

    // Find trailer
    ind_stop = sbuf.indexOf(trailer, ind_start);
    if (ind_stop == -1) {
      // No trailer was found. Maybe we didn't read enough data?
      // Try to read more data.
      throw new Base64Exception("No Trailer", Base64Exception.NO_TRAILER_EXCEPTION);
    }

    // Extract Base-64 encoded request and remove request from sbuf
    String base64pkcs = sbuf.substring(ind_start + header.length(), ind_stop - 1);
    sbuf = sbuf.substring(ind_stop + trailer.length());
    if (debug) {
      System.out.println("base64pkcs: " + base64pkcs + "******");
    }
    return base64pkcs;
  }

  /**
   * Get an array of PKCS10 certificate signing requests.
   * The file contains Base64 encoded signing requests, which are each bounded at
   * the beginning by -----BEGIN NEW CERTIFICATE REQUEST-----, and bounded at the
   * end by -----END NEW CERTIFICATE REQUEST-----.
   */
  public ArrayList getSigningRequests(InputStream reader)
    throws FileNotFoundException, IOException, SignatureException,
	   NoSuchAlgorithmException, InvalidKeyException
  {
    int len = 200;     // Size of a read operation
    int ind_start, ind_stop;
    byte [] bbuf = new byte[len];
    String sbuf = null;
    ArrayList pkcs10requests = new ArrayList();

    while (reader.available() > 0) {
      int read = reader.read(bbuf, 0, len);
      sbuf = sbuf + new String(bbuf, 0, read);

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
      //FileOutputStream f = new FileOutputStream("der.cer");
      //f.write(pkcs10DER);
      //f.close();
      if (debug) {
	System.out.println("PKCS10 Request:" + new String(Base64.encode(pkcs10DER)));
      }

      // Create PKCS10 object
      PKCS10 pkcs10 = getSigningRequest(pkcs10DER);
      pkcs10requests.add(pkcs10);
    }

    return pkcs10requests;
  }

  public ArrayList getSigningRequests(String filename)
    throws FileNotFoundException, IOException, SignatureException,
	   NoSuchAlgorithmException, InvalidKeyException
  {
    if (debug) {
      System.out.println("PKCS10 file: " + filename);
    }
    FileInputStream is = new FileInputStream(filename);
    return getSigningRequests(is);
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

  private synchronized int getNextSerialNumber(String filename)
    throws FileNotFoundException, IOException
  {
    String serialNbFileName = confDirectoryName + File.separatorChar + filename;
    if (debug) {
      System.out.println("Serial Number file name: " + serialNbFileName);
    }
    File fserial = new File(serialNbFileName);
    FileWriter fOutSerial = null;
    int nextSerialNumber = 0;
    String serialNbString = null;

    if (!fserial.exists()) {
      if (debug) {
	System.out.println("Serial Number file (" + serialNbFileName + 
			   ") does not exists. Creating...");
      }
      fserial = new File(serialNbFileName);
      try {
	fserial.createNewFile();
	fOutSerial = new FileWriter(fserial);
	nextSerialNumber = 1;
	serialNbString = String.valueOf(nextSerialNumber);
	fOutSerial.write(serialNbString, 0, serialNbString.length());
	fOutSerial.close();
      }
      catch (Exception e) {
	throw new FileNotFoundException("Unable to create serial number file: "
					+ fserial.getPath());
      }
    }
    FileReader fInSerial = new FileReader(fserial);
    char cbuf[] = new char[200];
    int byteRead = fInSerial.read(cbuf);
    fInSerial.close();
    serialNbString = new String(cbuf, 0, byteRead);
    System.out.println("Serial = " + serialNbString);
    nextSerialNumber = Integer.parseInt(serialNbString);

    // Write next serial number back to file.
    fOutSerial = new FileWriter(fserial);

    // For now, do a simple increment algorithm.
    serialNbString = String.valueOf(nextSerialNumber + 1);
    fOutSerial.write(serialNbString, 0, serialNbString.length());
    fOutSerial.close();

    return nextSerialNumber;
  }

  /** Sign a PKCS10 certificate signing request with a CA key
   */
  public X509CertImpl signX509Certificate(PKCS10 clientRequest)
    throws IOException, CertificateEncodingException, NoSuchAlgorithmException,
	   CertificateException, SignatureException, InvalidKeyException,
	   NoSuchProviderException
  {
    // Get X500 name of Certificate authority
    SignerInfo si = null;
    if (debug) {
      System.out.println("CA x509:" + caX509cert.toString());
    }

    if (debug) {
      //System.out.println("x500: " + caX500IssuerName.getCommonName());
    }

    // Get Signature object for certificate authority
    PrivateKey caPrivateKey = caKeyStore.getPrivateKey(caPolicy.alias);
    Signature caSignature = Signature.getInstance(caPrivateKey.getAlgorithm());
    // caSignature.initSign(caPrivateKey);

    X500Signer caX500signer = new X500Signer(caSignature, caX500Name);
    if (debug) {
      System.out.println("Signer: " + caX500signer);
    }

    /** 
     * Client certificate attributes
     * Valid attributes:
     *  version, serialNumber, algorithmID, issuer, validity, subject, key
     *  issuerID, subjectID, extensions
     */
    X509CertImpl clientCertificate = setX509CertificateFields(clientRequest);

    // Set subject unique ID
    /*
    CertificateSubjectUniqueIdentity certSubjectUniqueIdentity = new CertificateSubjectUniqueIdentity();
    clientCertInfo.set("subjectuniqueid", certSubjectUniqueIdentity);
    */
    

    // Sign certificate
    if (debug) {
      System.out.println("Before signing: " + clientCertificate.toString());
    }
    clientCertificate.sign(caPrivateKey, caPolicy.algorithmId.getName());
    if (debug) {
      System.out.println("After signing: " + clientCertificate.toString());
    }

    return clientCertificate;
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

  private boolean isBase64(InputStream inputstream)
    throws IOException
  {
    if(inputstream.available() >= 10) {
      inputstream.mark(10);
      int i = inputstream.read();
      int j = inputstream.read();
      int k = inputstream.read();
      int l = inputstream.read();
      int i1 = inputstream.read();
      int j1 = inputstream.read();
      int k1 = inputstream.read();
      int l1 = inputstream.read();
      int i2 = inputstream.read();
      int j2 = inputstream.read();
      inputstream.reset();
      return i == 45 && j == 45 && k == 45 && l == 45 && i1 == 45 && j1 == 66 && k1 == 69 && l1 == 71 && i2 == 73 && j2 == 78;
    } else {
      throw new IOException("Cannot determine encoding format");
    }
  }

  private byte[] getTotalBytes(InputStream inputstream)
    throws IOException
  {
    byte abyte0[] = new byte[8192];
    ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream(2048);
    bytearrayoutputstream.reset();
    int i;
    while((i = inputstream.read(abyte0, 0, abyte0.length)) != -1) 
      bytearrayoutputstream.write(abyte0, 0, i);
    return bytearrayoutputstream.toByteArray();
  }


  private byte[] base64_to_binary(InputStream inputstream)
    throws IOException
  {
    long l = 0L;
    inputstream.mark(inputstream.available());
    BufferedInputStream bufferedinputstream = new BufferedInputStream(inputstream);
    BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(bufferedinputstream));
    String s;
    if((s = readLine(bufferedreader)) == null || !s.startsWith("-----BEGIN"))
      throw new IOException("Unsupported encoding");
    l += s.length();
    StringBuffer stringbuffer = new StringBuffer();
    for(; (s = readLine(bufferedreader)) != null && !s.startsWith("-----END"); stringbuffer.append(s));
    if(s == null) {
      throw new IOException("Unsupported encoding");
    } else {
      l += s.length();
      l += stringbuffer.length();
      inputstream.reset();
      inputstream.skip(l);
      BASE64Decoder base64decoder = new BASE64Decoder();
      return base64decoder.decodeBuffer(stringbuffer.toString());
    }
  }


  private String readLine(BufferedReader bufferedreader)
    throws IOException
  {
    int defaultExpectedLineLength = 80;
    StringBuffer stringbuffer = new StringBuffer(defaultExpectedLineLength);
    int i;
    do {
      i = bufferedreader.read();
      stringbuffer.append((char)i);
    } while(i != -1 && i != 10 && i != 13);
    if(i == -1)
      return null;
    if(i == 13) {
      bufferedreader.mark(1);
      int j = bufferedreader.read();
      if(j == 10)
	stringbuffer.append((char)i);
      else
	bufferedreader.reset();
    }
    return stringbuffer.toString();
  }


  private Collection parseX509orPKCS7Cert(InputStream inputstream)
    throws CertificateException
  {
    try {
      inputstream.mark(inputstream.available());
      X509CertImpl x509certimpl = new X509CertImpl(inputstream);
      System.out.println("X509: " + x509certimpl);
      
      // Print DN
      X500Name x500Name = new X500Name(x509certimpl.getSubjectDN().toString());
      System.out.println("DN: " + x509certimpl.getSubjectDN().toString());
      return Arrays.asList(new X509Certificate[] {
	x509certimpl
      });
    }
    catch(CertificateException certificateexception) { }
    catch(IOException ioexception1) {
      throw new CertificateException(ioexception1.getMessage());
    }
    try {
      inputstream.reset();
      PKCS7 pkcs7 = new PKCS7(inputstream);
      System.out.println("PKCS7: " + pkcs7);

      X509Certificate ax509certificate[] = pkcs7.getCertificates();
      if(ax509certificate != null)
	return Arrays.asList(ax509certificate);
      else
	return new ArrayList(0);
    }
    catch(IOException ioexception) {
      throw new CertificateException(ioexception.getMessage());
    }
  }

  private X509CertImpl setX509CertificateFields(PKCS10 clientRequest)
    throws IOException, CertificateException
  {
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
    int nextSerialNumber = getNextSerialNumber(caPolicy.serialNumberFile);
    CertificateSerialNumber certSerialNumber = new CertificateSerialNumber(nextSerialNumber);
    clientCertInfo.set("serialNumber", certSerialNumber);

    // Set algorithm ID
    CertificateAlgorithmId certAlgorithmId =
      new CertificateAlgorithmId(caPolicy.algorithmId);
    clientCertInfo.set("algorithmID", certAlgorithmId);

    // Set issuer
    CertificateIssuerName certIssuerName = new CertificateIssuerName(caX500Name);
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

    // Set key
    clientCertInfo.set("key", clientCertificateX509Key);

    X509CertImpl clientCertificate = new X509CertImpl(clientCertInfo);

    return clientCertificate;
  }

  public static void main(String[] args) {
    String option = args[0];

    String caDN = "CN=NCA, OU=CONUS, O=DLA, L=Washington D.C., ST=DC, C=US";
    try {
      KeyManagement km = null;
      km = new KeyManagement(caDN);
      if (option.equals("-10")) {
	FileInputStream f = new FileInputStream(args[1]);
	PrintStream ps = new PrintStream(System.out);
	km.processPkcs10Request(ps, f);
	/*
	  BufferedReader pkcs10stream = null;
	  PrintStream dbgout = new PrintStream(System.out);
	  String pkcs10filename = args[1];
	  PKCS10 pkcs10Request = null;
	  ArrayList pkcs7Certificates = new ArrayList();
	  try {
	  ArrayList pkcs10req = km.getSigningRequests(pkcs10filename);
	  for (int i = 0 ; i < pkcs10req.size() ; i++) {
	  pkcs7Certificates.add(km.signX509Certificate((PKCS10)pkcs10req.get(i)));
	  }
	  }
	  catch (Exception e) {
	  System.out.println("Exception: " + e);
	  e.printStackTrace();
	  }
	*/

      }
      else if (option.equals("-7")) {
	FileInputStream is = new FileInputStream(args[1]);
	km.printPkcs7Request(is);
	// km.printPkcs7Request(args[1]);
      }
    } catch (Exception e) {
      System.out.println("Exception: " + e);
      e.printStackTrace();      
    }
  }
}


