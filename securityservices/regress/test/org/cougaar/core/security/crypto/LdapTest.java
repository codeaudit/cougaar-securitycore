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

package test.org.cougaar.core.security.crypto;

import junit.framework.Assert;
import junit.framework.TestCase;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.CertDirectoryServiceRequestorImpl;
import org.cougaar.core.security.crypto.NodeConfiguration;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceCA;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;

import test.org.cougaar.core.security.simul.BasicNode;

public class LdapTest
  extends TestCase
{
  private BasicNode bn;
  private CertDirectoryServiceCA caOperations = null;
  private CertDirectoryServiceClient certificateFinder=null;
  private ServiceBroker serviceBroker;
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
    serviceBroker = bn.getServiceBroker();

  }

  public void runTest() {

    String url = "ldap://pear:389/dc=JunitTest,dc=cougaar,dc=org";
    String caDN = "CN=NCA_CA, OU=CONUS, O=DLA, L=San Francisco, ST=CA, C=US";

    NodeConfiguration nodeConfiguration =
      new NodeConfiguration(caDN,
			    secProvider.getServiceBroker());

    CertDirectoryServiceRequestor cdsr =
      new CertDirectoryServiceRequestorImpl(url,
					    TrustedCaPolicy.COUGAAR_OPENLDAP, caDN, "test",
					    serviceBroker);
    caOperations = (CertDirectoryServiceCA)
      serviceBroker.getService(cdsr, CertDirectoryServiceCA.class, null);

    cdsr =
      new CertDirectoryServiceRequestorImpl(url,
					    TrustedCaPolicy.COUGAAR_OPENLDAP, caDN, "test",
					    serviceBroker);
    certificateFinder = (CertDirectoryServiceClient)
      serviceBroker.getService(cdsr, CertDirectoryServiceClient.class, null);

    //certificateFinder.getContexts();

  }
}
