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

package com.nai.security.test.crypto;

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

// Cougaar
import org.cougaar.util.ConfigFinder;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceRevokedListener;
import org.cougaar.core.component.ServiceRevokedEvent;

// Cougaar Security Services
import com.nai.security.policy.*;
import com.nai.security.crypto.*;
import com.nai.security.util.*;
import com.nai.security.crypto.ldap.CertDirectoryServiceCA;
import com.nai.security.crypto.ldap.CertDirectoryServiceFactory;
import com.nai.security.crypto.ldap.CertificateRevocationStatus;

import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import com.nai.security.crypto.ldap.CertDirectoryServiceClient;


public class LdapTest {
  private CertDirectoryServiceCA caOperations = null;
  private CertDirectoryServiceClient certificateFinder=null;
  private SecurityPropertiesService secprop = null;

  public void runTest(String[] args) {

    String url = args[0];

    String caDN = "CN=NCA_CA, OU=CONUS, O=DLA, L=San Francisco, ST=CA, C=US";

    // TODO. Modify following line to use service broker instead
    secprop = SecurityServiceProvider.getSecurityProperties(null);

    NodeConfiguration nodeConfiguration = new NodeConfiguration(caDN);

    String role = secprop.getProperty(secprop.SECURITY_ROLE);
    if (role == null && CryptoDebug.debug == true) {
      System.out.println("warning: Role not defined");
    }

    caOperations =
      CertDirectoryServiceFactory.getCertDirectoryServiceCAInstance(
	TrustedCaPolicy.COUGAAR_OPENLDAP, url);

    certificateFinder = 
	CertDirectoryServiceFactory.getCertDirectoryServiceClientInstance(
				     TrustedCaPolicy.COUGAAR_OPENLDAP,
				     url);
    certificateFinder.getContexts();

  }

  public static void main(String[] args) {
    LdapTest lt = new LdapTest();
    lt.runTest(args);
  }
}
