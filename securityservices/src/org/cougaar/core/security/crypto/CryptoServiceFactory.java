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

package org.cougaar.core.security.crypto;

import java.lang.*;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceBrokerSupport;

import com.nai.security.util.CryptoDebug;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.services.identity.*;

public class CryptoServiceFactory {

  private ServiceBroker serviceBroker;
  private CryptoManagerServiceProvider cryptoServiceProvider;

  public void initCryptoServices()
  {
    // Add cryptographic related services

    if (serviceBroker == null) {
      throw new RuntimeException("Service Broker not set");
    }

    cryptoServiceProvider = new CryptoManagerServiceProvider();

    registerServices();
  }

  public void setServiceBroker(ServiceBroker sb)
  {
    serviceBroker = sb;
  }

  private void registerServices()
  {
    if (CryptoDebug.debug) {
      System.out.println("Registering cryptographic services");
    }

    /* Register cryptographic services.
     */
    serviceBroker.addService(AgentMobilityService.class,
			     cryptoServiceProvider);

    serviceBroker.addService(CertificateManagementService.class,
			     cryptoServiceProvider);

    serviceBroker.addService(DataProtectionService.class,
			     cryptoServiceProvider);

    serviceBroker.addService(IdentityService.class,
			     cryptoServiceProvider);

    serviceBroker.addService(PublicKeyRingService.class,
			     cryptoServiceProvider);

    serviceBroker.addService(MessageService.class,
			     cryptoServiceProvider);

    serviceBroker.addService(PrivateKeyRingService.class,
			     cryptoServiceProvider);

  }

}
