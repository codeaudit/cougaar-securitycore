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

// Cougaar core services
import org.cougaar.core.service.*;

// Cougaar security services
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.provider.SecurityServiceProvider;

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

    /** 1) */

    SecurityServiceProvider secProvider = null;
    MessageProtectionService mps = null;
    secProvider = new SecurityServiceProvider();

    mps =
      (MessageProtectionService)secProvider.getService(null,
						       this,
						       MessageProtectionService.class);

    /** 2) */

    /** 3) */
    Assert.assertTrue(false);
  }
}
