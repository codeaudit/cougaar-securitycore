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

import java.util.Map;

import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.auth.JaasClient;
import org.cougaar.core.security.provider.BaseSecurityServiceProvider;
import org.cougaar.core.security.services.auth.PedigreeService;
import org.cougaar.core.service.AgentIdentificationService;

/**
 * 
 * @author srosset
 *
 * The provider of the PedigreeService. The provider is instantiated once
 * per agent, and the implementation of the PedigreeService is instantiated
 * once per agent.
 *  
 * There is no restriction on what component can retrieve the PedigreeService,
 * however only security components can set the pedigree. Ordinary plugins have
 * read-only access to the pedigree data.
 */
public class PedigreeServiceProvider
extends BaseSecurityServiceProvider
{
  /**
   * The instance of the PedigreeService for the current agent.
   */
  private PedigreeService pedigreeService;
  
  /**
   * This provider is instantiated once per agent. myAgentName is the name of the
   * agent under which the current instance of the provider has been instantiated. 
   */
  private String myAgentName;
  
  public PedigreeServiceProvider(ServiceBroker sb,
      String community, boolean checkPermission) {
    super(sb, community, checkPermission);
    AgentIdentificationService ais = (AgentIdentificationService)
    sb.getService(this, AgentIdentificationService.class, null);
    myAgentName = ais.getName();
    pedigreeService = new PedigreeServiceImpl(sb);
    if (log.isDebugEnabled()) {
      log.debug("PedigreeServiceProvider. Agent name: " + myAgentName);
    }
  }
  
  /**
   * Get a service.
   * @param sb a Service Broker
   * @param requestor the requestor of the service
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @return a service
   */
  protected synchronized Service getInternalService(ServiceBroker sb, 
      Object requestor, Class serviceClass) {
    
    /* Obtaining the agent name from the JaasClient is not
     * strictly necessary, however it is shown here to demonstrate
     * how one can retrieve the agent name from the JaasClient.
     * The agent name obtained from the agentIdentification service
     * can be forged more easily than the name retrieved from the JaasClient. 
     */
    
    String jaasAgentName = JaasClient.getAgentName();
    if (log.isDebugEnabled()) {
      log.debug("getInternalService. JAAS Agent name:" + jaasAgentName
          + " - AIS agent name: " + myAgentName);
    }
    if (jaasAgentName != null && (!jaasAgentName.equals(myAgentName))) {
      if (log.isWarnEnabled()) {
        log.warn("Agent name retrieved from JaasClient does not match "
            + "name retrieved from AgentIdentificationService");
      }
    }
    Service svc = null;
    if (PedigreeService.class.isAssignableFrom(serviceClass)) {
      svc = pedigreeService;
    }
    return svc;
  }
  
  /** Release a service.
   * @param sb a Service Broker.
   * @param requestor the requestor of the service.
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @param service the service to be released.
   */
  protected void releaseInternalService(ServiceBroker sb,
      Object requestor,
      Class serviceClass,
      Object service) {
  }
}
