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

package test.org.cougaar.core.security.test.crypto;

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
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.util.*;
import org.cougaar.core.security.crypto.ldap.CertDirectoryServiceCA;
import org.cougaar.core.security.crypto.ldap.CertDirectoryServiceFactory;
import org.cougaar.core.security.crypto.ldap.CertificateRevocationStatus;

import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.crypto.ldap.CertDirectoryServiceClient;

import junit.framework.*;

// Regress
import test.org.cougaar.core.security.simul.BasicNode;

public class LdapTest
  extends TestCase
{
  private BasicNode bn;
  private CertDirectoryServiceCA caOperations = null;
  private CertDirectoryServiceClient certificateFinder=null;
  private SecurityPropertiesService secprop = null;
  private SecurityServiceProvider secProvider;

  public LdapTest(String name) {
    super(name);
    secProvider = new SecurityServiceProvider();
  }

  public void setUp() {
    // Initialize Basic Node
    bn = new BasicNode();
    Assert.assertNotNull("Could not get Basic Node", bn);

    secProvider = bn.getSecurityServiceProvider();

    secprop = (SecurityPropertiesService)
      secProvider.getService(null,
			     this,
			     SecurityPropertiesService.class);
    Assert.assertNotNull("Could not get SecurityPropertiesService",
			 secprop);
  }

  public void runTest() {

    String url = "ldap://pear:389/dc=JunitTest,dc=cougaar,dc=org";
    String caDN = "CN=NCA_CA, OU=CONUS, O=DLA, L=San Francisco, ST=CA, C=US";

    NodeConfiguration nodeConfiguration =
      new NodeConfiguration(caDN,
			    secProvider.getServiceBroker());

    String role = secprop.getProperty(secprop.SECURITY_ROLE);
    if (role == null) {
      System.out.println("warning: Role not defined");
    }

    caOperations =
      CertDirectoryServiceFactory.getCertDirectoryServiceCAInstance(
	TrustedCaPolicy.COUGAAR_OPENLDAP, url,
	secProvider.getServiceBroker());

    certificateFinder = 
	CertDirectoryServiceFactory.getCertDirectoryServiceClientInstance(
				     TrustedCaPolicy.COUGAAR_OPENLDAP,
				     url,
	secProvider.getServiceBroker());
    certificateFinder.getContexts();

  }
}
