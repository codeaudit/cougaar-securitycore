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

package org.cougaar.core.security.access.message;

import java.util.ArrayList;

import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.ContainerAPI;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceFilterBinder;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.access.AccessPermission;
import org.cougaar.core.security.policy.mediator.OwlMessagePolicyMediator;
import org.cougaar.core.security.services.policy.PolicyService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class MessageAccessAgentBinder extends ServiceFilterBinder  {

  private transient ServiceBroker serviceBroker;
  protected static Logger log; 
  
  public  MessageAccessAgentBinder (BinderFactory bf,Object child) {
    super(bf,child);
    log = LoggerFactory.getInstance().createLogger(MessageAccessAgentBinder.class);
  }

  protected ContainerAPI createContainerProxy() {
    if(log!=null){
      if(log.isDebugEnabled()){
        log.debug("createContainerProxy created for MessageAccessAgentBinder");
      }
    }
    return new ServiceFilterContainerProxy();
  }

  protected ServiceBroker createFilteringServiceBroker(ServiceBroker sb) {
    if(log.isDebugEnabled()){
      log.debug("createFilteringServiceBroker created for MessageAccessAgentBinder");
    }
    if(sb != null) {
      if(log.isDebugEnabled()){
        log.debug("createFilteringServiceBroker sb is not null will create logger");
      } 
      log = (LoggingService)sb.getService(this, LoggingService.class, null);
      if(log == null) {
        log = LoggerFactory.getInstance().createLogger(this);
      }
    }
    if(log.isDebugEnabled()){
      log.debug("Creating Access Agent Service Broker ");
    }
    return new AccessAgentServiceBroker(sb);
  }
 
  protected class AccessAgentServiceBroker extends FilteringServiceBroker implements MessageAccess {

    private transient MessageAddress agentAddress;

    public AccessAgentServiceBroker(ServiceBroker sb) {
      super(sb);
      //AgentIdentificationService ais = (AgentIdentificationService)
      //sb.getService(this, AgentIdentificationService.class, null);
      agentAddress = MessageAddress.getMessageAddress(getComponentDescription().getName()); 
    }
   
    /* ******************************************************************************************
     * BEGIN AccessPolicyClient Interface
     * ******************************************************************************************/
    public String getName(){
      return agentAddress.toString();
    }

    /* ******************************************************************************************
     * END AccessPolicyClient Interface 
     * ******************************************************************************************/

    protected Object getServiceProxy(Object service, Class serviceclass, Object client)  {
      if(service instanceof MessageTransportService) {
        serviceBroker = getServiceBroker();
        PolicyService ps=null;
        if (serviceBroker != null)  {
          ps = (PolicyService)
            serviceBroker.getService(this,PolicyService.class, null);
          if (ps ==null){
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
	System.out.println("Creating Msg proxy. Requestor:" + client.getClass().getName()
                           + ". Service: " + serviceclass.getName());
	if(security != null) {
	  security.checkPermission(new AccessPermission(serviceclass.getName()));
	}	
	if(PolicyService.USE_DAML){
          if(log.isDebugEnabled()){
            log.debug("Creating DamlMessageAccessAgentProxy ");
          }
	  OwlMessagePolicyMediator pm= new OwlMessagePolicyMediator(serviceBroker,new ArrayList());
	  return new OwlMessageAccessAgentProxy((MessageTransportService)service,client,ps,
                                                serviceBroker);
	}
	else {
	  if(log.isDebugEnabled()){
            log.debug("Creating DamlMessageAccessAgentProxy ");
          }
	  return new XmlMessageAccessAgentProxy((MessageTransportService)service,client,ps,
                                                serviceBroker);
        }
	  
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
