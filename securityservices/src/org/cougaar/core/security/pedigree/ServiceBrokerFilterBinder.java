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
package org.cougaar.core.security.pedigree;

import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.ContainerAPI;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceFilterBinder;
import org.cougaar.core.component.ServiceRevokedListener;
import org.cougaar.core.domain.RootPlan;
import org.cougaar.core.security.auth.JaasClient;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainForBlackboardService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

/**
 * 
 * @author srosset
 *
 * A binder that wraps ServiceBrokers and returns proxies to the following services:
 * - RootPlan
 * - DomainForBlackboardService
 * - BlackboardService
 */
public class ServiceBrokerFilterBinder
extends ServiceFilterBinder
{
  private static Logger _log;
  static {
    _log = LoggerFactory.getInstance().createLogger(ServiceBrokerFilterBinder.class);
  }
  
  public ServiceBrokerFilterBinder(BinderFactory bf, Object child) {
    super(bf,child);
    /*
    if (_log.isDebugEnabled()) {
      _log.debug("Instantiating binder: " + this + " Child:" + child);
    }
    */
  }
  
  public void load() {
    super.load();
  }
  
  /** define to choose the class of the BinderProxy.  
   * Should usually be an extension of ServiceFilterBinderProxy.
   * The default creates and returns an instance of ServiceFilterContainerProxy.
   **/
  protected ContainerAPI createContainerProxy() { 
    return new ServiceFilterContainerProxy();
  }
  
  // this method installs the "filtering" service broker
  protected ServiceBroker createFilteringServiceBroker(ServiceBroker sb) {
    return new ServiceBrokerFilter(sb); 
  }
  
  private class ServiceBrokerFilter 
  extends FilteringServiceBroker
  {
    public ServiceBrokerFilter(ServiceBroker sb) {
      super(sb);
    }
    
    /**
     * This implementation of getService calls allowService(serviceClass).  If allowService 
     * returns true, will then call getClientProxy to proxy the client, delegates to the real broker
     * to request the service, then calls getServiceProxy to wrap the service. <p>
     **/
    public Object getService(Object requestor, Class service, ServiceRevokedListener srl) {
      return super.getService(requestor, service, srl);
    }
    
    /** Specifies an alternative instance to use as the service
     * implementation passed back to the client component.
     * @param client is the client object passed up to the real service broker.  
     * This is usually the requestor, but may be a proxy for the requestor if
     * getClientProxy was exercised.
     **/
    protected Object getServiceProxy(Object service, Class serviceClass, Object client) {
      //if (_log.isDebugEnabled()) {
      //  _log.debug("getServiceProxy:" + serviceClass.getName());
      //}
      if (service instanceof RootPlan) {
        logExecutionContext(client);
        return new RootPlanProxy((RootPlan) service, getServiceBroker());
      } 
      else if (service instanceof DomainForBlackboardService) {
        return new DomainForBlackboardServiceProxy(
            (DomainForBlackboardService)service, getServiceBroker());
      }
      else if (service instanceof BlackboardService) {
        return new BlackboardServiceProxy((BlackboardService) service, getServiceBroker());
      } 
      // Otherwise, no proxy.
      return null;
    }
    
    private void logExecutionContext(Object client) {
      if (_log.isDebugEnabled()) {
        _log.debug("getServiceProxy. Client: " + client + "/" + JaasClient.getComponentName());
      }
    }
    
    protected  void releaseServiceProxy(Object serviceProxy, Object service, Class serviceClass) {
    }
  }
}