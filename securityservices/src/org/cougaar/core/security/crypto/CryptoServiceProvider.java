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
import java.util.Hashtable;

// Cougaar
import org.cougaar.core.component.ServiceProvider;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.Service;
import org.cougaar.core.component.ContainerSupport;
import org.cougaar.core.component.ContainerAPI;
import org.cougaar.core.component.StateObject;

// Security Services
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.crypto.*;

import com.nai.security.certauthority.KeyManagement;
import com.nai.security.crypto.KeyRing;

public class CryptoServiceProvider 
  extends ContainerSupport
  implements ContainerAPI, ServiceProvider, StateObject
{
  private Hashtable services;

  public CryptoServiceProvider() {
    services = new Hashtable();

    /* Agent mobility service */
    services.put(AgentMobilityService.class,
		 AgentMobilityServiceImpl.class);

    /* Certificate Management service */
    services.put(CertificateManagementService.class,
		 KeyManagement.class);

    /* Key lookup service */
    services.put(KeyRingService.class,
		 KeyRing.class);

    /*
    services.put(DataProtectionService.class,
		 DataProtectionServiceImpl.class);
    */
  }

  /** ******************************************************************
   *  BindingSiteAPI implementation
   */
  public void requestStop() {};

  /** ******************************************************************
   *  ServiceProvider implementation
   */
  public Object getService(ServiceBroker sb, Object obj, Class cls) {
    Class serviceClass = (Class) services.get(cls);
    Object service = null;

    if (cls == KeyRing.class) {
      service = getKeyRingService();
    }
    else {
      try {
	service = serviceClass.newInstance();
      }
      catch (java.lang.InstantiationException e) {
      }
      catch (java.lang.IllegalAccessException e) {
      }
    }
    return service;
  }
  
  public void releaseService(ServiceBroker sb, Object obj1,
			     Class cls, Object obj2)
  {
  }

  /** ******************************************************************
   *  ContainerAPI implementation
   */
  public ContainerAPI getContainerProxy() {
    return this;
  }

  // We're not using this yet but leave it in anyway.
  protected String specifyContainmentPoint() {
    return "Node.CryptoProvider";
  }

  /** ******************************************************************
   *  StateObject Model API implementation
   */
  
  // Return a (serializable) snapshot that can be used to
  // reconstitute the state later.
  public Object getState() {
    // TBD
    return null;
  }
  // Reconstitute from the previously returned snapshot.
  public void setState(Object state) {
  }

  /** ******************************************************************
   */
  static private KeyRingService keyRingService;

  private KeyRingService getKeyRingService()
  {
    /* Create a singleton class for now
     */
    synchronized (keyRingService) {
      if (keyRingService == null) {
	keyRingService = new KeyRing();
      }
    }
    return keyRingService;
  }

  /** *********************************************
   * TODO
   * Temporary hack until the keyring service is fully
   * componentized.
   */
  public static KeyRingService getKeyRing()
  {
    /* Create a singleton class for now
     */
    synchronized (keyRingService) {
      if (keyRingService == null) {
	keyRingService = new KeyRing();
      }
    }
    return keyRingService;
  }
}
