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

package org.cougaar.core.security.provider;

import java.lang.*;
import java.util.Hashtable;

// Cougaar core services
import org.cougaar.core.component.*;
import org.cougaar.util.*;


// Cougaar security services
import com.nai.security.util.CryptoDebug;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.services.acl.*;
import org.cougaar.core.security.services.identity.*;
import org.cougaar.core.security.services.util.*;

public class SecurityServiceProvider
  extends ContainerSupport
  implements ContainerAPI, ServiceProvider, StateObject
{
  private ServiceBroker serviceBroker;
  private Hashtable services;
  private boolean initDone = false;

  public SecurityServiceProvider() {
    setServiceBroker();
    registerServices();
  }

  public SecurityServiceProvider(ServiceBroker sb) {
    serviceBroker = sb;
    registerServices();
  }

  /** **********************************************************************
   * StateModel Interface
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

  /** **********************************************************************
   * End StateModel Interface
   */

  /** **********************************************************************
   * ServiceProvider Interface
   */
  public Object getService(ServiceBroker sb,
			   Object requestor,
			   Class serviceClass) {
    if (CryptoDebug.debug) {
      System.out.println("Security Service Request: "
			 + requestor.getClass().getName()
			 + " - " + serviceClass.getName());
    }
    ServiceProvider servMgr = null;
    Service service = null;
    try {
      servMgr = (ServiceProvider) services.get(serviceClass);
      service = (Service) servMgr.getService(sb,
					     requestor,
					     serviceClass);
    }
    catch (Exception e) {
      System.out.println("Unable to get service request");
      e.printStackTrace();
    }
    if (service == null) {
      System.out.println("Warning: Service not registered: " + serviceClass.getName());
    }
    return service;
  }

  public void releaseService(ServiceBroker sb,
			     Object requestor,
			     Class serviceClass,
			     Object service) {
  }

  /** **********************************************************************
   * End ServiceProvider Interface
   */

  /** **********************************************************************
   * BindingSite Interface
   */
  public void requestStop() {
  }

  public ContainerAPI getContainerProxy() {
    return this;
  }

  // We're not using this yet but leave it in anyway.
  protected String specifyContainmentPoint() {
    return "Node.SecurityServiceProvider";
  }

  public ServiceBroker getServiceBroker() {
    // if for testing purpose this function will return null by base class
    ServiceBroker sb = super.getServiceBroker();
    return (sb == null) ? serviceBroker : sb;
  }

  /** **********************************************************************
   * End BindingSite Interface
   */

  /** **********************************************************************
   * Private methods
   */
  private void setServiceBroker()
  {
    ServiceBroker sb = getServiceBroker();
    if (sb == null) {
      // Install a default broker. This is only for test purposes
      System.out.println("WARNING: Running in a test environment");
      serviceBroker = new ServiceBrokerSupport();
    }
    else {
      serviceBroker = sb;
    }
  }

  private void registerServices() {
    services = new Hashtable();

    if (CryptoDebug.debug) {
      System.out.println("Registering security services");
    }

    /* ********************************
     * Property service
     */
    services.put(SecurityPropertiesService.class,
		 new SecurityPropertiesServiceProvider());
    serviceBroker.addService(SecurityPropertiesService.class, this);

    /* ********************************
     * Configuration services
     */
    services.put(ConfigParserService.class,
		 new ConfigParserServiceProvider());
    serviceBroker.addService(ConfigParserService.class, this);

    /* ********************************
     * Encryption services
     */
    /* Certificate Management service */
    services.put(CertificateManagementService.class,
		 new CertificateManagementServiceProvider());
    serviceBroker.addService(CertificateManagementService.class, this);

    /* Key lookup service */
    services.put(KeyRingService.class,
		 new KeyRingServiceProvider());
    serviceBroker.addService(KeyRingService.class, this);

    /* Encryption Service */
    services.put(EncryptionService.class,
		 new EncryptionServiceProvider());
    serviceBroker.addService(EncryptionService.class, this);

    /* Data protection service */
    serviceBroker.addService(DataProtectionService.class, this);


    /* ********************************
     * Identity services
     */
    /* Agent identity service */
    services.put(AgentIdentityService.class,
		 new AgentIdentityServiceProvider());
    serviceBroker.addService(AgentIdentityService.class, this);

    /* ********************************
     * Access Control services
     */

    /* ********************************
     * Policy services
     */
    services.put(AccessControlPolicyService.class,
		 new AccessControlPolicyServiceProvider());
    serviceBroker.addService(AccessControlPolicyService.class, this);

    services.put(CryptoPolicyService.class,
		 new CryptoPolicyServiceProvider());
    serviceBroker.addService(CryptoPolicyService.class, this);

    services.put(ServletPolicyService.class,
		 new ServletPolicyServiceProvider());
    serviceBroker.addService(ServletPolicyService.class, this);

    /* ********************************
     * SSL services
     */
    services.put(SSLService.class,
		 new SSLServiceProvider());
    serviceBroker.addService(SSLService.class, this);
    serviceBroker.getService(this, SSLService.class, null);
    services.put(WebserverIdentityService.class,
		 new WebserverSSLServiceProvider());
    serviceBroker.addService(WebserverIdentityService.class, this);

    /* ********************************
     * LDAP user administration
     */
    services.put(LdapUserService.class, new LdapUserServiceProvider());
    serviceBroker.addService(LdapUserService.class, this);
    serviceBroker.getService(this, LdapUserService.class, null);
  }

  /* ******************************************************************
   * HACK. FIX TODO
   */
  public static SecurityPropertiesService
  getSecurityProperties(javax.servlet.Servlet servlet)
    {
    ServiceProvider servMgr = new SecurityPropertiesServiceProvider();
    SecurityPropertiesService service =
      (SecurityPropertiesService)
      servMgr.getService(null,
			 servlet,
			 SecurityPropertiesService.class);
    return service;
  }
}
