/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 * Created on May 08, 2002, 2:42 PM
 */

package org.cougaar.core.security.access;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceFilterBinder;
import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.ContainerAPI;
import org.cougaar.core.agent.Agent;
import org.cougaar.core.agent.AgentBinder;
import org.cougaar.core.agent.AgentManagerForBinder;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.core.security.services.acl.AccessControlPolicyService;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.LoggingService;

public class AccessAgentBinder 
  extends ServiceFilterBinder 
  implements AgentBinder {

  private ServiceBroker serviceBroker;
  private LoggingService log;

  public  AccessAgentBinder (BinderFactory bf,Object child) {
    super(bf,child);
  }
  
  /* ********************************************************************************
   * AgentBinder interface
   */
  /**
   * Get the agent's message address.
   */
  public MessageAddress getAgentIdentifier() {
    AgentBinder ab = (AgentBinder) getChildBinder();
    if (ab == null) {
      log.error("Unable to get child binder");
      throw new RuntimeException("AccessAgentBinder: Unable to get child binder");
    }

    MessageAddress ret = ab.getAgentIdentifier();
    if (log == null) {
      serviceBroker = getServiceBroker();
      log = (LoggingService) serviceBroker.getService(this,LoggingService.class, null);
    }

    if (log.isDebugEnabled()) {
      log.debug("getAgentIdentifier of agent "+ret);
    }
    return ret;
  }

  /**
   * Obtain direct access to the agent.
   * <p>
   * This method may be removed from the binder API due to
   * security concerns.
   */
  public Agent getAgent() {
    AgentBinder ab = (AgentBinder) getChildBinder();
    MessageAddress addr = ab.getAgentIdentifier();
    Agent ret = ab.getAgent();
    if (log.isDebugEnabled()) {
      log.debug("getAgent of agent " + addr);
    }
    return ret;
  }
  
  /* ********************************************************************************
   * End AgentBinder interface
   */

  //child binder
  protected final AgentBinder getAgentBinder() { 
    return (AgentBinder)getChildBinder(); 
  }    
  //parent
  protected final AgentManagerForBinder getAgentManager() { 
    return (AgentManagerForBinder)getContainer(); 
  }
  
  protected ContainerAPI createContainerProxy() {
    return new AccessAgentBinderProxy();
  }

  protected ServiceBroker createFilteringServiceBroker(ServiceBroker sb) {
    return new AccessAgentServiceBroker(sb);
  }

  protected class AccessAgentBinderProxy
    extends ServiceFilterContainerProxy
    implements AgentManagerForBinder
  {
    public void registerAgent(Agent agent) {
      //just passing through
      getAgentManager().registerAgent(agent);
    }
    public String getName() {
      return getAgentManager().getName(); 
    }
    
  }
  
  protected class AccessAgentServiceBroker
    extends FilteringServiceBroker
    implements AccessPolicyClient  {
      
    public AccessAgentServiceBroker(ServiceBroker sb) {
      super(sb);
    }
   
    /* ******************************************************************************************
     * BEGIN AgentManagerForBinder Interface
     * ******************************************************************************************/
    public String getName(){
      return getAgentIdentifier().toString();
    }

    /* ******************************************************************************************
     * BEGIN FilteringServiceBroker
     * ******************************************************************************************/

    protected Object getServiceProxy(Object service, Class serviceclass, Object client)  {
      if(service instanceof MessageTransportService) {
	serviceBroker = getServiceBroker();
	AccessControlPolicyService acps=null;
	if (serviceBroker != null)  {
	  log = (LoggingService)
	    serviceBroker.getService(this,LoggingService.class, null);
	  acps = (AccessControlPolicyService)
	    serviceBroker.getService(this,AccessControlPolicyService.class, null);
	  if (acps == null) {
	    throw new RuntimeException("Message Access Crl Binder. No policy service");
	  }
	} else {
	  throw new RuntimeException("Message Access Control Binder: no service broker");
	}
	SecurityManager security = System.getSecurityManager();
	if (serviceclass == null) {
	  throw new IllegalArgumentException("Illegal service class");
	}
	log.debug("Creating Msg proxy. Requestor:" + client.getClass().getName()
		  + ". Service: " + serviceclass.getName());
	if(security != null) {
	  security.checkPermission(new AccessPermission(serviceclass.getName()));
	}	
      	return new AccessAgentProxy((MessageTransportService)service,client,acps,
				    serviceBroker);
	  
      }
      return null;
    }

    public void releaseService(Object requestor, Class serviceClass, Object service) {
      if (log.isDebugEnabled()) {
	log.debug("releaseService. requestor:" + requestor
	  + " service: " + service + " serviceClass: " +  serviceClass);
      }
      super.releaseService(requestor, serviceClass, service);
    }

    /** 
     * Called to release the AccessAgentProxy previously constructed by the binder.
     * This method is called before the real service is released.
     **/
    protected void releaseServiceProxy(Object serviceProxy, Object service, Class serviceClass) {
      if (log.isDebugEnabled()) {
	log.debug("releaseServiceProxy. serviceProxy:" + serviceProxy
	  + " service: " + service + " serviceClass: " +  serviceClass);
      }
      super.releaseServiceProxy(serviceProxy, service, serviceClass);
    }

  }
}
