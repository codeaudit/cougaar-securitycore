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
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.core.component.BinderWrapper;
import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.BinderSupport;
import org.cougaar.core.component.Component;
import org.cougaar.core.component.ComponentDescription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.PluginManagerForBinder;
import org.cougaar.core.plugin.Plugin;
import org.cougaar.core.plugin.PluginBase;
import org.cougaar.core.plugin.PluginBinder;
import org.cougaar.util.ConfigFinder;

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
  implements PluginManagerForBinder, PluginBinder
{
  private LoggingService _log;
  private ExecutionContext _ec;
  private SecurityContextService _scs;
  
  /** Creates new JaasPluginBinder */
  public JaasPluginBinder(BinderFactory bf, Object child) {
    super(bf,child);
  }

  /************************************************************
   * PluginManagerForBinder
   */

  public MessageAddress getAgentIdentifier() {
    return getPluginManager().getAgentIdentifier();
  }

  public ConfigFinder getConfigFinder() {
    return getPluginManager().getConfigFinder();
  }

  /************************************************************
   * End PluginManagerForBinder
   */
  
  public String toString() {
    return "JaasPluginBinder for " + getPluginManager();
  }

  private ClusterIdentifier getClusterIdentifier() {
    MessageAddress addr = getAgentIdentifier();
    ClusterIdentifier cid = null;
    if(addr instanceof ClusterIdentifier) {
      cid = (ClusterIdentifier)addr;
    }
    else {
      cid = new ClusterIdentifier(addr.getQosAttributes(), addr.getAddress()); 
    }
    return cid;
  }

  private PluginManagerForBinder getPluginManager() {
    return (PluginManagerForBinder)getContainer();
  }
  
  private String getPluginName(){
    // this method is exposed in cougaar 10.x release
    //return getComponentDescription().getClassname();
    return "dummy-plugin";
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
    _scs = (SecurityContextService)
      sb.getService(this, SecurityContextService.class, null);
    AuthorizationService as = (AuthorizationService)
	    sb.getService(this, AuthorizationService.class, null);
    // the getComponentDescription is exposed in cougaar 10.x
    //_ec = as.createExecutionContext(getClusterIdentifier(), getComponentDescription());
    // component description is null for now
    _ec = as.createExecutionContext(getClusterIdentifier(), null);
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
