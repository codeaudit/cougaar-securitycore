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
import org.cougaar.core.component.Binder;
import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.ContainerAPI;
import org.cougaar.core.agent.Agent;
import org.cougaar.core.agent.AgentManager;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.core.security.services.acl.AccessControlPolicyService;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.AgentIdentificationService;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class AccessAgentBinder 
  extends ServiceFilterBinder  {

  private ServiceBroker serviceBroker;
  private Logger log;

  public  AccessAgentBinder (BinderFactory bf,Object child) {
    super(bf,child);
  }

  protected ContainerAPI createContainerProxy() {
    return new ServiceFilterContainerProxy();
  }

  protected ServiceBroker createFilteringServiceBroker(ServiceBroker sb) {
    if(sb != null) {
      log = (LoggingService)sb.getService(this, LoggingService.class, null);
      if(log == null) {
        log = LoggerFactory.getInstance().createLogger(this);
      }
    }
    return new AccessAgentServiceBroker(sb);
  }
 
  protected class AccessAgentServiceBroker
    extends FilteringServiceBroker
    implements AccessPolicyClient  {
    private MessageAddress _agent;

    public AccessAgentServiceBroker(ServiceBroker sb) {
      super(sb);
      //AgentIdentificationService ais = (AgentIdentificationService)
        //sb.getService(this, AgentIdentificationService.class, null);
      _agent = MessageAddress.getMessageAddress(getComponentDescription().getName()); 
    }
   
    /* ******************************************************************************************
     * BEGIN AccessPolicyClient Interface
     * ******************************************************************************************/
    public String getName(){
      return _agent.toString();
    }

    /* ******************************************************************************************
     * END AccessPolicyClient Interface 
     * ******************************************************************************************/

    protected Object getServiceProxy(Object service, Class serviceclass, Object client)  {
      if(service instanceof MessageTransportService) {
	serviceBroker = getServiceBroker();
	AccessControlPolicyService acps=null;
	if (serviceBroker != null)  {
	  acps = (AccessControlPolicyService)
	    serviceBroker.getService(this,AccessControlPolicyService.class, null);
	  if (acps == null && !AccessAgentProxy.USE_DAML) {
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
