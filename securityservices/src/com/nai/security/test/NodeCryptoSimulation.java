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

package com.nai.security.test;

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
import java.math.BigInteger;

import javax.crypto.*;

import javax.naming.directory.SearchResult;
import javax.naming.directory.Attributes;
import sun.security.pkcs.*;
import sun.security.x509.*;
import sun.security.util.*;
import sun.security.provider.*;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

// Cougaar core services
import org.cougaar.util.ConfigFinder;
import org.cougaar.core.component.ServiceBrokerSupport;

// Cougaar Security Services
import com.nai.security.policy.*;
import com.nai.security.crypto.*;
import com.nai.security.certauthority.KeyManagement;
import com.nai.security.util.*;
import com.nai.security.crypto.ldap.CertDirectoryServiceCA;
import com.nai.security.crypto.ldap.CertDirectoryServiceFactory;
import com.nai.security.crypto.ldap.CertificateRevocationStatus;

import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.provider.SecurityServiceProvider;

public class NodeCryptoSimulation
{
  private KeyRingService keyRing = null;
  private SecurityServiceProvider secProvider = null;

  public NodeCryptoSimulation()
  {
    secProvider = new SecurityServiceProvider();

    keyRing = (KeyRingService)secProvider.getService(null,
						     this,
						     KeyRingService.class);
  }

  public static void main(String[] args) {
    NodeCryptoSimulation ncs = new NodeCryptoSimulation();
    ncs.runTest(args);
  }

  private void runTest(String[] args)
  {
    String option = args[0];
    String role = args[1];

    if (CryptoDebug.debug) {
      System.out.println("Option is : " + option);
    }

    setupCryptoService();

    try {
      if (option.equals("-10")) {
	sendPkcs10Request(role, args[2]);
      }
      else if (option.equals("-7")) {
	sendPkcs7Request(role, args[2]);
      }
      else if (option.equals("-1")) {
	simulNode(role, args[2]);
      }
    } catch (Exception e) {
      System.out.println("Exception: " + e);
      e.printStackTrace();      
    }
  }

//  CryptoSecurityComponent csf;

  private void setupCryptoService()
  {
//    csf = new CryptoSecurityComponent();
//    csf.setServiceBroker(new ServiceBrokerSupport());
//    csf.initCryptoServices();
  }

  private void sendPkcs10Request(String role, String filename)
    throws Exception
  {
    String caDN = "CN=NCA_CA, OU=CONUS, O=DLA, L=San Francisco, ST=CA, C=US";

    // Process a PKCS10 request:
    KeyManagement km = null;
    km = new KeyManagement(caDN, role, null, null, false, null);

    FileInputStream f = new FileInputStream(filename);
    PrintStream ps = new PrintStream(System.out);
    km.processPkcs10Request(ps, f);
  }

  private void sendPkcs7Request(String role, String filename)
    throws Exception
  {
    String caDN = "CN=NCA_CA, OU=CONUS, O=DLA, L=San Francisco, ST=CA, C=US";

    // Process a signed certificate request
    KeyManagement km = null;
    km = new KeyManagement(caDN, role, null, null, false, null);

    FileInputStream is = new FileInputStream(filename);
    km.printPkcs7Request(is);
    // km.printPkcs7Request(args[1]);
  }

  private void simulNode(String role, String nodeCN)
    throws Exception
  {
    /* - Search for the private key of an agent specified on the
     *   command line.
     * - Search for the public key of that same entity.
     * - It will create the key pair if it does not exist already:
     *    1) Create a self-signed certificate and key pair for the node.
     *    2) Send a PKCS10 request for the node to the CA.
     *    3) CA signs node's certificate
     *    4) CA stores node's certificate in file system and LDAP.
     *    5) Wait for the reply from the CA.
     *    6) Install the node's certificate signed by the CA.
     *    7) Create a self-signed certificate and key pair for the agent.
     *    8) Sign the agent's certificate with the node's private key.
     *    9) Send agent's certificate to the CA
     *    10) CA publishes agent's certificate to LDAP directory service.
     */

    String cn = nodeCN;
    if (CryptoDebug.debug) {
      System.out.println("Search private key for " + cn);
    }
    PrivateKey pk = keyRing.findPrivateKey(cn);
    if (CryptoDebug.debug) {
      System.out.println("Private key is : " + pk);
      System.out.println(" ========================================");
      System.out.println("Search cert for " + cn);
    }
    Certificate c = keyRing.findCert(cn);
    if (CryptoDebug.debug) {
      System.out.println("Certificate is : " + c);
    }
    System.out.println(" ========================================");
    //testEncryptionUsingRSA(c, args[3]);
  }

  private void testEncryptionUsingRSA(Certificate cert, String spec)
  {
    try {
      if (CryptoDebug.debug) {
	System.out.println("Trying RSA encryption using existing key");
      }
      PublicKey key = cert.getPublicKey();
      testRSAencryption(key, spec);

      if (CryptoDebug.debug) {
	System.out.println("===================================");
	System.out.println("Trying RSA encryption using new key");
      }
      KeyCertGenerator kc = new KeyCertGenerator(spec, "MD5WithRSA",
						 "IBMJCE");
      kc.generate(512);
      testRSAencryption(kc.getPublicKey(), spec);
      if (CryptoDebug.debug) {
	System.out.println("===================================");
      }
    } catch (Exception e) {
      System.out.println("Exception: " + e);
      e.printStackTrace();      
    }
  }

  private void testRSAencryption(PublicKey key, String spec)
  {
    try {
      if (CryptoDebug.debug) {
	System.out.println("Encrypting using " + spec);
      }
      /*init the cipher*/
      Cipher ci;
      ci=Cipher.getInstance(spec);
      ci.init(Cipher.ENCRYPT_MODE, key);
      String theObjectToEncrypt = "Secret Message";
      SealedObject so = new SealedObject(theObjectToEncrypt, ci);
    } catch (Exception e) {
      System.out.println("Exception: " + e);
      e.printStackTrace();      
    }
  }
}
