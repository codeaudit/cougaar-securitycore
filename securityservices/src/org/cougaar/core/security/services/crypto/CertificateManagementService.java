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

package org.cougaar.core.security.services.crypto;

import java.util.ArrayList;
import java.util.Collection;
import java.io.PrintStream;
import java.io.InputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import java.security.SignatureException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;

import sun.security.pkcs.PKCS10;
import sun.security.x509.X509CertImpl;

// Cougaar core services
import org.cougaar.core.component.Service;
import org.cougaar.core.security.certauthority.CertificateResponse;

public interface CertificateManagementService
  extends Service
{
  public void processX509Request(PrintStream out, InputStream inputstream);

  /** Process a PKCS10 request
   */
  public X509Certificate[] processPkcs10Request(InputStream request);

  public void publishCertificate(X509Certificate clientX509,int type, PrivateKey privateKey);
    
  

  public String processPkcs10Request(InputStream request, boolean replyInHtml);

  public CertificateResponse processPkcs10Request(PKCS10 request);

  public ArrayList getSigningRequests(InputStream reader)
    throws FileNotFoundException, IOException, SignatureException,
	   NoSuchAlgorithmException, InvalidKeyException;

  public ArrayList getSigningRequests(String filename)
    throws FileNotFoundException, IOException, SignatureException,
	   NoSuchAlgorithmException, InvalidKeyException;

  public PKCS10 getSigningRequest(byte[] bytes)
    throws IOException, SignatureException, NoSuchAlgorithmException,
	   InvalidKeyException;

  public X509CertImpl signX509Certificate(PKCS10 clientRequest)
    throws IOException, CertificateEncodingException, NoSuchAlgorithmException,
	   CertificateException, SignatureException, InvalidKeyException,
	   NoSuchProviderException;

  public ArrayList readX509Certificates(String filename)
    throws FileNotFoundException, CertificateException, IOException;

  public ArrayList parsePkcs7Certificate(String filename)
    throws FileNotFoundException, CertificateException, IOException;

  public int  revokeCertificate(String caDN ,String userUniqueIdentifier)
    throws IOException,Exception,CertificateException;

  public int  revokeAgentCertificate(String caDN ,String agentName)
    throws IOException,Exception,CertificateException;
    
  public Collection printPkcs7Request(InputStream inputstream)
    throws CertificateException;
}
