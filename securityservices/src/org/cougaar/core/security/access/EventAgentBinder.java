/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
 */

package org.cougaar.core.security.access;

import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.ContainerAPI;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceFilterBinder;
import org.cougaar.core.component.ServiceFilterBinder.FilteringServiceBroker;

import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.EventService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class EventAgentBinder  extends ServiceFilterBinder  {

  private ServiceBroker serviceBroker;
  private Logger log;

  public  EventAgentBinder (BinderFactory bf,Object child) {
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
    return new EventAgentServiceBroker(sb);
  }
 
  protected class EventAgentServiceBroker  extends FilteringServiceBroker  {
    
    public EventAgentServiceBroker(ServiceBroker sb) {
      super(sb);
      
    }
   
    protected Object getServiceProxy(Object service, Class serviceclass, Object client)  {
      if(service instanceof EventService) {
	serviceBroker = getServiceBroker();
	if (serviceBroker == null)  {
          throw new RuntimeException("Event Service  Control Binder: no service broker");
	}
        if(log.isDebugEnabled()){
          log.debug("Creating Event  proxy. Requestor:" + client.getClass().getName()
		  + ". Service: " + serviceclass.getName());
        }
        return new EventAgentProxy((EventService)service,client,serviceBroker);
	  
      }
      return null;
    }

    public void releaseService(Object requestor, Class serviceClass, Object service) {
      if(service instanceof EventService) {
        if (log.isDebugEnabled()) {
          log.debug("releaseService. requestor:" + requestor
                    + " service: " + service + " serviceClass: " +  serviceClass);
        }
        super.releaseService(requestor, serviceClass, service);
      }
    }

    /** 
     * Called to release the EventAgentProxy previously constructed by the binder.
     * This method is called before the real service is released.
     **/
    protected void releaseServiceProxy(Object serviceProxy, Object service, Class serviceClass) {
      if(service instanceof EventService) {
        if (log.isDebugEnabled()) {
          log.debug("releaseServiceProxy. serviceProxy:" + serviceProxy
                    + " service: " + service + " serviceClass: " +  serviceClass);
        }
        super.releaseServiceProxy(serviceProxy, service, serviceClass);
      }
    }

  }
}
