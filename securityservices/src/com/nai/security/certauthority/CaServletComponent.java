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

package com.nai.security.certauthority;

import java.io.*;
import java.lang.reflect.*;
import javax.servlet.*;
import javax.servlet.http.*;

// Cougaar core infrastructure
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.NamingService;

// Cougaar security services
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.services.crypto.CertificateManagementService;

public class CaServletComponent
  extends BaseServletComponent
{
  private String myPath = null;
  private Class myServletClass = null;
  private Servlet myServlet = null;

  private ClusterIdentifier agentId;
  private SecurityServletSupport support;

  // Services
  private BlackboardService blackboardService;
  private NamingService namingService;
  private SecurityPropertiesService securityPropertiesService;
  private CertificateManagementService certificateManagementService;

  /**
   * Capture the (optional) load-time parameters.
   * <p>
   * This is typically a List of Strings.
   */
  public void setParameter(Object o) {
    // Set path here
    String aPath = null;
    myPath = aPath;

    // Set servlet class here
    String aClass = null;
    try {
      myServletClass = Class.forName(aClass);
    }
    catch (Exception e) {}
  }

  public void load() {
    // FIXME need AgentIdentificationService
    org.cougaar.core.plugin.PluginBindingSite pbs =
      (org.cougaar.core.plugin.PluginBindingSite) bindingSite;
    this.agentId = pbs.getAgentIdentifier();

    
    // get the blackboard service
    blackboardService = (BlackboardService)
      serviceBroker.getService(
		    this,
		    BlackboardService.class,
		    null);
    if (blackboardService == null) {
      throw new RuntimeException(
          "Unable to obtain blackboard service");
    }

    // Get the naming service
    namingService = (NamingService)
      serviceBroker.getService(
		    this,
		    NamingService.class,
		    null);
    if (namingService == null) {
      throw new RuntimeException(
          "Unable to obtain naming service");
    }

    // Get the security properties service
    securityPropertiesService = (SecurityPropertiesService)
      serviceBroker.getService(
		    this,
		    SecurityPropertiesService.class,
		    null);
    if (securityPropertiesService == null) {
      throw new RuntimeException(
          "Unable to obtain security properties service");
    }
    
    // Get the security properties service
    certificateManagementService = (CertificateManagementService)
      serviceBroker.getService(
		    this,
		    CertificateManagementService.class,
		    null);
    if (certificateManagementService == null) {
      throw new RuntimeException(
          "Unable to obtain certoficate management service");
    }

    support = new SecurityServletSupportImpl(getPath(),
					     agentId,
					     blackboardService,
					     namingService,
					     securityPropertiesService,
					     certificateManagementService,
					     serviceBroker);
    super.load();
  }

  public void unload() {
    super.unload();
    // release the blackboard service
    if (blackboardService != null) {
      serviceBroker.releaseService(
        this, BlackboardService.class, blackboardService);
    }

    // release the naming service
    if (namingService != null) {
      serviceBroker.releaseService(
        this, NamingService.class, namingService);
    }

    // release the security properties service
    if (securityPropertiesService != null) {
      serviceBroker.releaseService(
        this, SecurityPropertiesService.class, securityPropertiesService);
    }

    // release the certificate management service
    if (certificateManagementService != null) {
      serviceBroker.releaseService(
        this, CertificateManagementService.class,
	certificateManagementService);
    }
  }

  protected String getPath() {
    return myPath;
  }

  protected Servlet createServlet() {
    Object o = null;
    try {
      // All security servlets have the same constructor
      Class[] constructorParam = new Class[1];
      constructorParam[0] = SecurityServletSupport.class;
      Constructor constructor =
	myServletClass.getConstructor(constructorParam);

      SecurityServletSupport[] arg = new SecurityServletSupport[1];
      arg[0] = support;
      o = constructor.newInstance(arg);
    }
    catch (Exception e) {}
    if (o == null || !(o instanceof Servlet)) {
      return null;
    }
    return (Servlet) o;
  }
}
