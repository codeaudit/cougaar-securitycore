/*
 * <copyright>
 *  Copyright 1997-2003 Networks Associates Technology, Inc.
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
 * 
 */

package org.cougaar.core.security.access;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.component.BinderWrapper;
import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.ComponentDescription;
import org.cougaar.util.ConfigFinder;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.JaasClient;
import org.cougaar.core.security.services.auth.AuthorizationService;
import org.cougaar.core.security.services.auth.SecurityContextService;

/**
 * add following line to the .ini file to activate this binder:
 * Node.AgentManager.Agent.PluginManager.Binder = org.cougaar.core.security.access.JaasPluginBinderFactory
 *
 */
public class JaasPluginBinder
  extends BinderWrapper
{
  private Logger _log;
  private ExecutionContext _ec;
  private SecurityContextService _scs;
  private MessageAddress _agent;
 
  /** Creates new JaasPluginBinder */
  public JaasPluginBinder(BinderFactory bf, Object child) {
    super(bf,child);
  }

  public String toString() {
    return "JaasPluginBinder for " + getContainer();
  }

  private String getPluginName(){
    return getComponentDescription().getClassname();
  }

  private void doLoad() {
    super.load();
  }
  
  private void doStart() { 
    super.start();
  }
  
  public void load() {
    ServiceBroker sb = getServiceBroker();
    _log = (LoggingService)
      sb.getService(this, LoggingService.class, null);
    if(_log == null) {
      _log = LoggerFactory.getInstance().createLogger(this); 
    }
    _scs = (SecurityContextService)
      sb.getService(this, SecurityContextService.class, null);
    AgentIdentificationService ais = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null);
    _agent = ais.getMessageAddress();
    AuthorizationService as = (AuthorizationService)
	    sb.getService(this, AuthorizationService.class, null);
    // the getComponentDescription is exposed in cougaar 10.x
    _ec = as.createExecutionContext(_agent, getComponentDescription());
    _scs.setExecutionContext(_ec);
    JaasClient jc = new JaasClient(_ec);
    jc.doAs(getPluginName(),
            new java.security.PrivilegedAction() {
                public Object run() {
                  _log.debug("Plugin manager is loading: "
			    + getPluginName()
			    + " security context is:");
                  JaasClient.printPrincipals();
                  doLoad();
                  return null;
                }
              }, true);
     _scs.resetExecutionContext();
  }

   
  public void start() {
    _scs.setExecutionContext(_ec);
    JaasClient jc = new JaasClient(_ec);
    jc.doAs(getPluginName(),
            new java.security.PrivilegedAction() {
                public Object run() {
                  _log.debug("Plugin manager is starting: "
			    + getPluginName()
			    + " security context is:");
                  JaasClient.printPrincipals();
                  doStart();
                  return null;
                }
              }, false);
    _scs.resetExecutionContext();
  }
}
