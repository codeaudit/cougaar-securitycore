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

import java.io.*;
import java.util.*;
import java.security.cert.*;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.security.pkcs.*;
import sun.security.x509.*;
import com.nai.security.util.CryptoDebug;
public class CertificateUtility {
  //private static boolean debug = false;

  public static final String PKCS10HEADER  = "-----BEGIN NEW CERTIFICATE REQUEST-----";
  public static final String PKCS10TRAILER = "-----END NEW CERTIFICATE REQUEST-----";

  public static final String PKCS7HEADER   = "-----BEGIN CERTIFICATE-----";
  public static final String PKCS7TRAILER  = "-----END CERTIFICATE-----";
  public static int CACert=1;
  public static int EntityCert=2;
  /*
  static {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
  }
  */
  public static Collection parseX509orPKCS7Cert(InputStream inputstream)
    throws CertificateException
  {
    try {
      inputstream.mark(inputstream.available());
      X509CertImpl x509certimpl = new X509CertImpl(inputstream);
      if (CryptoDebug.debug) {
	System.out.println("X509: " + x509certimpl);
      }
      
      // Print DN
      X500Name x500Name = new X500Name(x509certimpl.getSubjectDN().toString());
      if (CryptoDebug.debug) {
	System.out.println("DN: " + x509certimpl.getSubjectDN().toString());
      }
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
    if (CryptoDebug.debug) {
      System.out.println("base64pkcs: " + base64pkcs + "******");
    }
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
    StringBuffer buff=new StringBuffer("<br>");
    buff.append("&nbsp;&nbsp;&nbsp;&nbsp;");
    int blockcount=0;
    int linecount=0;
    for(int i = 0; i < data.length; i++) {
      String digit = Integer.toHexString(data[i] & 0x00ff);
      if(digit.length() < 2)buff.append("0");
      buff.append(digit);
      blockcount++;
      if(blockcount>1)
      {
	buff.append("&nbsp;&nbsp;&nbsp;&nbsp;");
	blockcount=0;
	linecount++;
      }
      if(linecount>7)
      {
	linecount=0;
	blockcount=0;
	buff.append("<br>");
	buff.append("&nbsp;&nbsp;&nbsp;&nbsp;");
      }
    }
    return buff.toString();
  }

}
