/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
 
 
 
 
 
 
 
 


package org.cougaar.core.security.access;

import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.ContainerAPI;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceFilterBinder;
import org.cougaar.core.service.EventService;
import org.cougaar.core.service.LoggingService;
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
