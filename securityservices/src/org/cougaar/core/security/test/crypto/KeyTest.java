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

package org.cougaar.core.security.test.crypto;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.services.crypto.KeyRingService;

import java.util.List;

public class KeyTest implements Runnable
{
  private String commonName = null;
  private KeyRingService keyRing = null;
  private SecurityServiceProvider secProvider = null;

  public KeyTest(String aCN)
  {
    commonName = aCN;

    secProvider = new SecurityServiceProvider();
    ServiceBroker sb = secProvider.getServiceBroker();
    keyRing = (KeyRingService)sb.getService(this, KeyRingService.class, null);
  }

  public void run() {
    // Retrieve same key from multiple threads.
    List c = keyRing.findCert(commonName, KeyRingService.LOOKUP_LDAP);
  }

}
