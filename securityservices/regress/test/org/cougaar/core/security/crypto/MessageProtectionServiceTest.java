/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 * Created on September 12, 2001, 10:55 AM
 */

package test.org.cougaar.core.security.crypto;

import junit.framework.*;

import java.io.*;

// Cougaar core services
import org.cougaar.core.service.*;
import org.cougaar.core.component.*;
import org.cougaar.core.mts.*;

// Cougaar security services
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.provider.SecurityServiceProvider;

// Regress
import test.org.cougaar.core.security.simul.BasicNode;

public class MessageProtectionServiceTest
  extends TestCase
{

  public MessageProtectionServiceTest(String name) {
    super(name);
  }

  public static Test suite() {
    return new TestSuite(MessageProtectionServiceTest.class);
  }

  /**
   * A test case method consists of:
   * 1) Code which creates the objects we will interact with during the test.
   *    This testing context is commonly referred to as a test's fixture.
   * 2) Code which exercises the objects in the fixture.
   * 3) Code which verifies the result.
   */
  public void testEncryption() {
    // Initialize Basic Node
    BasicNode bn = new BasicNode();
    Assert.assertNotNull("Could not get Basic Node", bn);

    SecurityServiceProvider secProvider = bn.getSecurityServiceProvider();

    // Get Message Protection Service
    MessageProtectionService mps = 
      (MessageProtectionService)secProvider.getService(bn.getServiceBroker(),
						       this,
						       MessageProtectionService.class);
    Assert.assertNotNull("Could not get MessageProtectionService", mps);

    // Create a test header
    String header = "Source:foo - Target:bar";
    byte[] rawData = header.getBytes();
    MessageAddress source = new MessageAddress("foo");
    MessageAddress destination = new MessageAddress("bar");
    byte[] encryptedHeader = null;
    byte[] decryptedHeader = null;

    // Encrypt header
    encryptedHeader = mps.protectHeader(rawData,
					source,
					destination);
    Assert.assertNotNull("Encrypted Header is null", encryptedHeader);
   
    // Decrypt header
    decryptedHeader = mps.unprotectHeader(encryptedHeader,
					  source,
					  destination);
    String newHeader = new String (decryptedHeader);
    Assert.assertNotNull("Deccrypted Header is null", decryptedHeader);

    // Original header and (encrypted then decrypted) header should be equal.
    Assert.assertEquals(header, newHeader);

    // Original header and encrypted header should be different
    // (but of course that does not guarantee that encryption is done properly)
    boolean isDifferent = !header.equals(new String(encryptedHeader));
    Assert.assertTrue(isDifferent);

    System.out.println("Header before encryption: " + header);
    //System.out.println("Header after encryption: " + new String(encryptedHeader));
    System.out.println("Header after encryption/decryption: " + newHeader);

    // 
    OutputStream os = null;
    InputStream is = null;
    MessageAttributes attrs = null;

    ProtectedOutputStream pos =
      mps.getOutputStream(os,
			  source,
			  destination,
			  attrs);
    ProtectedInputStream pis =
      mps.getInputStream(is,
			 source,
			 destination,
			 attrs);

  }
}
