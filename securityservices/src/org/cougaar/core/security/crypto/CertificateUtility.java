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

import org.cougaar.core.security.policy.CertificateAttributesPolicy;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.StringTokenizer;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.security.pkcs.PKCS7;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.OIDMap;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;

public class CertificateUtility {
  //private static boolean debug = false;

  public static final String PKCS10HEADER =
  "-----BEGIN NEW CERTIFICATE REQUEST-----";
  public static final String PKCS10TRAILER =
  "-----END NEW CERTIFICATE REQUEST-----";

  public static final String PKCS10HEADER_ARR[]  = {
    "-----", "BEGIN", "CERTIFICATE REQUEST", "-----"};
  public static final String PKCS10TRAILER_ARR[] = {
    "-----", "END", "CERTIFICATE REQUEST", "-----"};

  public static final String PKCS7HEADER   = "-----BEGIN CERTIFICATE-----";
  public static final String PKCS7TRAILER  = "-----END CERTIFICATE-----";
  public static final int CACert=1;
  public static final int EntityCert=2;
  private static Logger _log;

  static {
    _log = LoggerFactory.getInstance().createLogger(CertificateUtility.class);
  }
  public static Collection parseX509orPKCS7Cert(InputStream inputstream)
    throws CertificateException
    {
      try {
	inputstream.mark(inputstream.available());
	X509CertImpl x509certimpl = new X509CertImpl(inputstream);
	/*
	  if (CryptoDebug.debug) {
	  System.out.println("X509: " + x509certimpl);
	  // Print DN
	  System.out.println("DN: " + x509certimpl.getSubjectDN().toString());
	  }
	*/
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
	//System.out.println("PKCS7: " + pkcs7);

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

  private static String readLine(BufferedReader bufferedreader)
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

  public static String getBase64Block(String sbuf, String header, String trailer)
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
      //if (CryptoDebug.debug) {
      //System.out.println("base64pkcs: " + base64pkcs + "******");
      //}
      return base64pkcs;
    }


  public static String base64encode(byte [] der, String header, String trailer)
    throws IOException
    {
      ByteArrayOutputStream b = new ByteArrayOutputStream(500);
      base64encode(b, der, header, trailer);
      return b.toString("US-ASCII");
    }

  public static void base64EncodeCertificates(OutputStream out, X509Certificate[] certs)
    throws CertificateEncodingException, IOException
    {
      for (int i = 0 ; i < certs.length ; i++) {
	base64encode(out, certs[i].getEncoded(), PKCS7HEADER, PKCS7TRAILER);
      }
    }

  public static void base64encode(OutputStream out, byte [] der,
				  String header, String trailer)
    throws IOException
    {
      String h = header + "\n";
      String t = trailer + "\n";

      out.write(h.getBytes());
      BASE64Encoder b64 = new BASE64Encoder();
      b64.encodeBuffer(der, out);
      out.write(t.getBytes());
    }

  public static boolean isBase64(InputStream inputstream)
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

  public static byte[] base64_to_binary(InputStream inputstream)
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

  public static String toHexinHTML(byte[] data)
    {
      StringBuffer buff=new StringBuffer("");
      buff.append("&nbsp;&nbsp;");
      int blockcount=0;
      int linecount=0;
      for(int i = 0; i < data.length; i++) {
	String digit = Integer.toHexString(data[i] & 0x00ff);
	if(digit.length() < 2)buff.append("0");
	buff.append(digit);
	blockcount++;
	if(blockcount>1)
	  {
	    buff.append("&nbsp;&nbsp;");
	    blockcount=0;
	    linecount++;
	  }
	if(linecount>7)
	  {
	    linecount=0;
	    blockcount=0;
	    buff.append("<br>");
	    buff.append("&nbsp;&nbsp;");
	  }
      }
      return buff.toString();
    }


  public static String getX500Domain(String aDN, boolean setType,
				     char separator, boolean keepOrder)
    {
      String domain = "";

      StringTokenizer parser = new StringTokenizer(aDN, ",=");
      while(parser.hasMoreElements()) {
	String tok1 = parser.nextToken().trim().toLowerCase();
	String tok2 = parser.nextToken();
	if (tok1.equals("dc")) {
	  if (keepOrder) {
	    if (domain.length() > 0) {
	      domain = domain + separator;
	    }
	    if (setType) {
	      domain = domain + tok1 + "=" + tok2;
	    }
	    else {
	      domain = domain + tok2;
	    }
	  }
	  else {
	    if (domain.length() > 0) {
	      domain = separator + domain;
	    }
	    if (setType) {
	      domain = domain + tok1 + "=" + tok2;
	    }
	    else {
	      domain = tok2 + domain;
	    }
	  }
	}
      }
      return domain;
    }

  public static void printCertificateDetails(PrintWriter out, X509Certificate  certimpl) {
    out.println("<b>Version&nbsp;&nbsp;&nbsp;:</b>"
		+certimpl.getVersion());
    out.println("<br>");
    out.println("<b>Subject&nbsp;&nbsp;&nbsp;:</b>"
		+certimpl.getSubjectDN().getName());
    out.println("<br>");
    out.println("<b>Signature Algorithm &nbsp;&nbsp;&nbsp;:</b>"
		+certimpl.getSigAlgName()
		+",<b>&nbsp;OID&nbsp; :</b>"+certimpl.getSigAlgOID());
    out.println("<br>");
    out.println("<b>Public Key&nbsp;&nbsp;&nbsp;:</b><PRE>"
		+CertificateUtility.toHexinHTML(certimpl.getPublicKey().getEncoded()) + "</PRE>");
    out.println("<br>");
    out.println("<b>Valid from &nbsp;:</b>"
		+certimpl.getNotBefore().toString());
    out.println("<b>&nbsp &nbsp;To &nbsp;:</b>"
		+certimpl.getNotAfter().toString());
    out.println("<br>");
    out.println("<b>Issuer &nbsp;&nbsp;:</b>"
		+certimpl.getIssuerDN().getName());
    out.println("<br>");
    out.println("<b>Serial No &nbsp;&nbsp;:</b>"
		+certimpl.getSerialNumber());
    out.println("<br>");

    out.println("<b>Key Usage &nbsp;&nbsp;&nbsp;:</b>");
    try {
      String s = OIDMap.getName(new ObjectIdentifier("2.5.29.15"));
      if(s != null) {
        KeyUsageExtension keyusageextension =
          (KeyUsageExtension)((X509CertImpl)certimpl).get(s);
        if (keyusageextension != null)
          out.println(keyusageextension.toString());
      }
    } catch (Exception ex) {
      out.println("Failed to get key usage. " + ex.toString());
    }

    out.println("<br>");

    out.println("<b>Algorithm &nbsp;&nbsp;:</b>"
		+certimpl.getPublicKey().getAlgorithm());
    out.println("<br>");
    out.println("<b>Signature &nbsp;&nbsp;:</b><PRE>"
		+ CertificateUtility.toHexinHTML(certimpl.getSignature())
		+ "</PRE>");
    out.println("<br>");
    // Fingerprint
    out.println("<b>MD5 fingerprint &nbsp;&nbsp;:</b><PRE>"
		+ getCertFingerPrint("MD5", certimpl)
		+ "</PRE>");
    out.println("<b>SHA1 fingerprint &nbsp;&nbsp;:</b><PRE>"
		+ getCertFingerPrint("SHA1", certimpl)
		+ "</PRE>");
    out.println("<br>");
  }

  private static String getCertFingerPrint(String s, Certificate certificate) {
    try {
      byte abyte0[] = certificate.getEncoded();
      MessageDigest messagedigest = MessageDigest.getInstance(s);
      byte abyte1[] = messagedigest.digest(abyte0);
      return CertificateUtility.toHexinHTML(abyte1);
    }
    catch (Exception  e) {
      //System.out.println("Unable to compute certificate fingerprint");
      return "Unable to compute fingerprint";
    }
  }

  public static String findAttribute(String dname, String attrib) {
    attrib = attrib + "=";
    StringTokenizer st = new StringTokenizer(dname, ",");
    String title = null;
    for (int i = 0 ; st.hasMoreTokens() ; i++) {
      String s = st.nextToken().trim().toLowerCase();
      if (s.startsWith(attrib)) {
        title = s.substring(attrib.length(), s.length());
        break;
      }
    }
    return title;
  }

  public static  X500Name getX500Name(String dname) {
    try {
      return new X500Name(dname);
    }
    catch (IOException iox) {

    }
    return null;
  }

  public static String  parseDNforFilter(String aDN) {

    StringBuffer filter = new StringBuffer("(&");
    StringTokenizer parser = new StringTokenizer(aDN, ",=");
    while(parser.hasMoreElements()) {
      String tok1 = parser.nextToken().trim().toLowerCase();
      if (tok1.equals("t"))
	tok1 = "title";
      String tok2 = parser.nextToken();

      filter.append( "(" + tok1 + "=" + tok2 + ")");
    }
    filter.append(")");
    return filter.toString();
  }

  public static String getX500DN(String commonName,String title , CertificateAttributesPolicy certAttribPolicy) {
    StringBuffer dn=new StringBuffer("cn=" + commonName);
    dn.append(", ou=" + certAttribPolicy.ou);
    dn.append(",o=" + certAttribPolicy.o);
    dn.append(",l=" + certAttribPolicy.l);
    dn.append(",st=" + certAttribPolicy.st);
    dn.append(",c=" + certAttribPolicy.c);
    dn.append(",t=" + title);
    return dn.toString();
  }

  public static  MessageDigest createDigest(String algorithm, byte[] data)
    throws NoSuchAlgorithmException   {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    // Create a digest
    md.reset();
    md.update(data);
    md.digest();
    return md;
  }

  public static  String toHex(byte[] data) {
    StringBuffer buff = new StringBuffer();
    for(int i = 0; i < data.length; i++) {
      String digit = Integer.toHexString(data[i] & 0x00ff);
      if(digit.length() < 2)buff.append("0");
      buff.append(digit);
    }
    return buff.toString();
  }

  public static String getUniqueIdentifier(X509Certificate cert) {
    return getDigestAlgorithm(cert) + "-" + getHashValue(cert);
  }

  public static String getDigestAlgorithm(X509Certificate cert) {
    String digestAlg = cert.getSigAlgName().substring(0,3);
    return digestAlg;
  }

  public static String getHashValue(X509Certificate cert) {
    MessageDigest certDigest;
    byte[] der = null;
    String hash = null;

    // Use the prefix of the signature algorithm for creating a DN
    // Acceptable values: SHA, MD2, MD4, MD5
    try {
      certDigest = MessageDigest.getInstance(getDigestAlgorithm(cert));
      der = cert.getTBSCertificate();
      certDigest.reset();
      certDigest.update(der);
      hash = toHex(certDigest.digest());
    }
    catch(Exception ex) {
      if (_log.isWarnEnabled()) {
	_log.warn("Unable to get message digest", ex);
      }
    }
    return hash;
  }

  public static X509Certificate getX509Certificate(Certificate cert) throws 
    CertificateEncodingException,CertificateException, IOException {
    InputStream inStream = new ByteArrayInputStream(cert.getEncoded());
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate x509cert = (X509Certificate)cf.generateCertificate(inStream);
    inStream.close();
    return x509cert;
  }

}
