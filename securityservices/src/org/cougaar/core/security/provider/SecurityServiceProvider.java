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
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.bootstrap.SystemProperties;
import org.cougaar.core.component.*;
import org.cougaar.util.*;
import org.cougaar.core.service.identity.*;
import org.cougaar.core.service.DataProtectionService;
import org.cougaar.core.service.MessageProtectionService;
import org.cougaar.core.node.NodeControlService;

import org.cougaar.core.service.LoggingService;
import org.cougaar.core.logging.LoggingControlService;
import org.cougaar.core.logging.LoggingServiceProvider;

// Cougaar security services
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.services.acl.*;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.services.identity.*;
import org.cougaar.core.security.provider.SecurityServicePermission;
import org.cougaar.core.security.util.*;

// Cougaar overlay
import org.cougaar.core.security.coreservices.crypto.*;

public class SecurityServiceProvider
  extends ContainerSupport
  implements ContainerAPI, ServiceProvider, StateObject
{
  private ServiceBroker serviceBroker;
  private ServiceBroker rootServiceBroker;
  private SecurityServiceTable services;
  private NodeControlService nodeControlService;
  private boolean initDone = false;
  private LoggingService log;

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
    if (log.isDebugEnabled()) {
      log.debug("Security Service Request: "
		+ requestor.getClass().getName()
		+ " - " + serviceClass.getName());
    }
    if (sb == null) {
      if (log.isWarnEnabled()) {
	log.warn("Running in a test environment");
      }
      sb = serviceBroker;
    }
    ServiceProvider servMgr = null;
    Service service = null;
    SecurityManager security = System.getSecurityManager();
    if( (security != null)&& (serviceClass!=null)) {
      log.debug(" !!! Going to check Security Permission for :"+serviceClass.getName()+
	"\nRequestor is "+requestor.getClass().getName()); 
      security.checkPermission(new SecurityServicePermission(serviceClass.getName()));
    }
    else 
      return service;
    try {
      servMgr = (ServiceProvider) services.get(serviceClass);
      service = (Service) servMgr.getService(sb,
					     requestor,
					     serviceClass);
    }
    catch (Exception e) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to get service request");
      }
      e.printStackTrace();
    }
    if (service == null) {
      if (log.isWarnEnabled()) {
	log.warn("Service not registered: " + serviceClass.getName());
      }
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
      serviceBroker = new ServiceBrokerSupport();
    }
    else {
      serviceBroker = sb;
    }
  }

  private void registerServices() {
    boolean isExecutedWithinNode = true;

    // Get root service broker
    nodeControlService = (NodeControlService)
      serviceBroker.getService(this, NodeControlService.class, null);
    if (nodeControlService != null) {
      rootServiceBroker = nodeControlService.getRootServiceBroker();
      if (rootServiceBroker == null) {
	throw new RuntimeException("Unable to get root service broker");
      }
    }
    else {
      // We are running outside a Cougaar node.
      // No Cougaar services are available.
      isExecutedWithinNode = false;
      rootServiceBroker = serviceBroker;

      /* ********************************
       * Logging service
       */
      // NodeAgent has not started the logging service at this point,
      // but we need it.
      // Removed because the Logging service is started early in 9.4

      LoggingServiceProvider loggingServiceProvider =
	new LoggingServiceProvider();
      rootServiceBroker.addService(LoggingService.class,
				   loggingServiceProvider);
      rootServiceBroker.addService(LoggingControlService.class,
				   loggingServiceProvider);
    }

    this.log = (LoggingService)
      rootServiceBroker.getService(this,
				   LoggingService.class, null);

    services = new SecurityServiceTable(log);

    if (log.isDebugEnabled()) {
      log.debug("Registering security services");
    }

    if (log.isInfoEnabled() && isExecutedWithinNode == false) {
      log.info("Running outside a Cougaar node");
    }

    /* ********************************
     * Property service
     */
    services.put(SecurityPropertiesService.class,
		 new SecurityPropertiesServiceProvider());
    rootServiceBroker.addService(SecurityPropertiesService.class, this);
    SecurityPropertiesService secprop = (SecurityPropertiesService)
      rootServiceBroker.getService(this, SecurityPropertiesService.class, null);
    boolean standalone = false;
    try {
    /*
      String nodeName = secprop.getProperty("org.cougaar.node.name",
    					"");
      if (nodeName == null || nodeName.equals(""))
        standalone = true;
        */
      standalone = new Boolean(secprop.getProperty(
        "org.cougaar.core.security.standalone", "false")).booleanValue();

      if (!standalone)
        new NodeInfo().setNodeName(serviceBroker);
    } catch (Exception ex) {
      log.warn("Unable to get value of standalone mode");
    }

    /* ********************************
     * Configuration services
     */
    services.put(ConfigParserService.class,
		 new ConfigParserServiceProvider());
    rootServiceBroker.addService(ConfigParserService.class, this);

    /* ********************************
     * Encryption services
     */
    /* Certificate Management service */
    services.put(CertificateManagementService.class,
                 new CertificateManagementServiceProvider());
    rootServiceBroker.addService(CertificateManagementService.class, this);

    /* Key lookup service */
    services.put(KeyRingService.class,
		 new KeyRingServiceProvider());
    rootServiceBroker.addService(KeyRingService.class, this);

    services.put(CertValidityService.class,
                 new CertValidityServiceProvider());
    rootServiceBroker.addService(CertValidityService.class, this);

    if (!standalone) {
      /* Encryption Service */
      services.put(EncryptionService.class,
                   new EncryptionServiceProvider());
      rootServiceBroker.addService(EncryptionService.class, this);

      /* Data protection service */
	/*
      services.put(DataProtectionService.class,
                   new DataProtectionServiceProvider());
      rootServiceBroker.addService(DataProtectionService.class, this);
*/

      /* Message protection service */
      services.put(MessageProtectionService.class,
                   new MessageProtectionServiceProvider());
      rootServiceBroker.addService(MessageProtectionService.class, this);

      /* ********************************
       * Identity services
       */
      /* Agent identity service */
      services.put(AgentIdentityService.class,
                   new AgentIdentityServiceProvider());
      rootServiceBroker.addService(AgentIdentityService.class, this);

      /* ********************************
       * Access Control services
       */

      /* ********************************
       * Policy services
       */
      services.put(PolicyBootstrapperService.class,
                   new PolicyBootstrapperServiceProvider());
      rootServiceBroker.addService(PolicyBootstrapperService.class, this);

      services.put(AccessControlPolicyService.class,
                   new AccessControlPolicyServiceProvider(serviceBroker));
      rootServiceBroker.addService(AccessControlPolicyService.class, this);

      services.put(CryptoPolicyService.class,
                   new CryptoPolicyServiceProvider(serviceBroker));
      rootServiceBroker.addService(CryptoPolicyService.class, this);

      services.put(ServletPolicyService.class,
                   new ServletPolicyServiceProvider(serviceBroker));
      rootServiceBroker.addService(ServletPolicyService.class, this);

    /* ********************************
     * SSL services
     */
      services.put(SSLService.class,
                   new SSLServiceProvider());
      rootServiceBroker.addService(SSLService.class, this);
      // SSLService and WebserverIdentityService are self started
      // they offer static functions to get socket factory
      // in the functions the permission will be checked.
      rootServiceBroker.getService(this, SSLService.class, null);

      // configured to use SSL?
      if (secprop.getProperty(secprop.WEBSERVER_HTTPS_PORT, null) != null) {
        services.put(WebserverIdentityService.class,
                     new WebserverSSLServiceProvider());
        rootServiceBroker.addService(WebserverIdentityService.class, this);
        rootServiceBroker.getService(this, WebserverIdentityService.class, null);
      }

      /* ********************************
       * LDAP user administration
       */
      services.put(LdapUserService.class,
                   new LdapUserServiceProvider());
      rootServiceBroker.addService(LdapUserService.class, this);
      org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm.
        setNodeServiceBroker(serviceBroker);
    }
    else {
      log.warn("Running in standalone mode");
      services.put(UserSSLService.class,
                   new UserSSLServiceProvider());
      rootServiceBroker.addService(UserSSLService.class, this);
    }

  }
}
