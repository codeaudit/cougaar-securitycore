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

package org.cougaar.core.security.certauthority;

import java.io.*;
import java.lang.reflect.*;
import java.util.List;
import java.util.Iterator;
import javax.servlet.*;
import javax.servlet.http.*;

// Cougaar core infrastructure
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.BlackboardQueryService;
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.NamingService;

// Cougaar security services
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.policy.*;

public class CaServletComponent
  extends BaseServletComponent
  implements BlackboardClient
{
  private String myPath = null;
  private Class myServletClass = null;
  private String myServletClassName = null;
  //private Servlet myServlet = null;

  private MessageAddress agentId;
  private SecurityServletSupport support;

  // Services
  private BlackboardService blackboardService;
  private BlackboardQueryService blackboardQueryService;
  //private CertificateManagementService certificateManagementService;
  private LoggingService log;

  public void Initialize() {
    /**
     * Set isCertAuth here, instead of loading it from cryptoClientPolicy
     */
    ConfigParserService configParser = (ConfigParserService)
      serviceBroker.getService(this,
					    ConfigParserService.class,
					    null);
    SecurityPolicy[] sp =
      configParser.getSecurityPolicies(CryptoClientPolicy.class);
    //CryptoClientPolicy cryptoClientPolicy = (CryptoClientPolicy) sp[0];
  }

  /**
   * Capture the (optional) load-time parameters.
   * <p>
   * This is typically a List of Strings.
   */
  public void setParameter(Object o) {
    // expecting a List of [String, String]
    if (!(o instanceof List)) {
      throw new IllegalArgumentException(
        "Expecting a List parameter, not : "+
        ((o != null) ? o.getClass().getName() : "null"));
    }
    List l = (List)o;
    if (l.size() != 2) {
      throw new IllegalArgumentException(
          "Expecting a List with two elements,"+
          " \"classname\" and \"path\", not "+l.size());
    }
    Object o1 = l.get(0);
    Object o2 = l.get(1);
    if ((!(o1 instanceof String)) ||
        (!(o2 instanceof String))) {
      throw new IllegalArgumentException(
          "Expecting two Strings, not ("+o1+", "+o2+")");
    }

    // save the servlet classname and path
    this.myServletClassName = (String) o1;
    this.myPath = (String) o2;

    // Set servlet class here
    try {
      myServletClass = Class.forName(myServletClassName);
    }
    catch (Exception e) {
      throw new IllegalArgumentException("Unable to find servlet class:"
					 + e);
    }
  }

  public void load() {
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    if (log.isDebugEnabled()) {
      log.debug("Loading servlet component: "
		+ myServletClassName + " at " + myPath);
    }

    AgentIdentificationService ais = (AgentIdentificationService)
      serviceBroker.getService(this, AgentIdentificationService.class, null);
    this.agentId = ais.getMessageAddress();

    if (this.agentId == null) {
      throw new RuntimeException("Unable to obtain agent identifier");
    }

    /*
    if (log.isDebugEnabled()) {
      log.debug("Currently available services:");
      Iterator it = serviceBroker.getCurrentServiceClasses();
      while (it.hasNext()) {
	log.debug(it.next().toString());
      }
    }
    */

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

    // get the blackboard query service
    blackboardQueryService = (BlackboardQueryService)
      serviceBroker.getService(
		    this,
		    BlackboardQueryService.class,
		    null);
    if (blackboardQueryService == null) {
      throw new RuntimeException(
          "Unable to obtain blackboard service");
    }
    
    NamingService ns = (NamingService)
      serviceBroker.getService(this, NamingService.class, null);
    support = new SecurityServletSupportImpl(getPath(),
					     agentId,
					     blackboardQueryService,
					     serviceBroker,
					     log, 
					     ns);

    super.load();
  }

  public void unload() {
    super.unload();
    // release the blackboard service
    if (blackboardService != null) {
      serviceBroker.releaseService(
        this, BlackboardService.class, blackboardService);
    }

    // release the blackboard query service
    if (blackboardQueryService != null) {
      serviceBroker.releaseService(
        this, BlackboardQueryService.class, blackboardQueryService);
    }

  }

  protected String getPath() {
    return myPath;
  }

  protected Servlet createServlet() {
    Object o = null;
    if (support == null) {
      throw new RuntimeException("Unable to initialize servlet: no security services");
    }

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
    catch (Exception e) {
      if (log.isErrorEnabled()) {
	e.printStackTrace();
	log.error("Unable to initialize servlet:" + e);
      }
    }
    if (o == null || !(o instanceof Servlet)) {
      return null;
    }
    Servlet servlet = (Servlet) o;
    return servlet;
  }

  public String toString() {
    return
      myServletClassName+"("+myPath+")";
  }

  /** ********************************************************************
   *  BlackboardClient implementation
   */

  // odd BlackboardClient method:
  public String getBlackboardClientName() {
    return toString();
  }

  // odd BlackboardClient method:
  public long currentTimeMillis() {
    throw new UnsupportedOperationException(
        this+" asked for the current time???");
  }

  // unused BlackboardClient method:
  public boolean triggerEvent(Object event) {
    // if we had Subscriptions we'd need to implement this.
    //
    // see "ComponentPlugin" for details.
    throw new UnsupportedOperationException(
        this+" only supports Blackboard queries, but received "+
        "a \"trigger\" event: "+event);
  }

}
