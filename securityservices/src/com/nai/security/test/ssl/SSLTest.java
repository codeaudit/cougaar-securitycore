/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
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
 */

package com.nai.security.test.ssl;

import org.cougaar.core.security.ssl.*;
import org.cougaar.core.security.provider.*;
import org.cougaar.core.security.services.crypto.*;
import com.nai.security.crypto.*;
import org.cougaar.core.component.*;

public class SSLTest {

  public static void main(String[] args) {
    new SSLTest();
  }

  public SSLTest() {
    ServiceBroker serviceBroker = new ServiceBrokerSupport();
    SecurityServiceProvider secProvider = new SecurityServiceProvider(serviceBroker);

    KeyRingService keyRing = (KeyRingService)secProvider.getService(serviceBroker,
						     this,
						     KeyRingService.class);

    try {
      SSLService sslservice = SSLServiceImpl.getInstance(keyRing);
    } catch (Exception e) {
      System.out.println("SSLService exception occurred.");
      e.printStackTrace();
    }
  }

}
