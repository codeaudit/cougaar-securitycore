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

package org.cougaar.core.security.provider;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceBrokerSupport;
import org.cougaar.core.component.ServiceProvider;
import org.cougaar.core.node.NodeControlService;
import org.cougaar.core.security.provider.policy.PolicyServiceProvider;
import org.cougaar.core.security.services.policy.PolicyService;
import org.cougaar.core.service.LoggingService;



public class PolicyServiceComponent  {
  private SecurityServiceTable services;
  private ServiceBroker serviceBroker;
  private ServiceBroker rootServiceBroker;
  private NodeControlService nodeControlService;
  private LoggingService log;
  private boolean isExecutedWithinNode = true;
  private boolean initDone = false;
  private String mySecurityCommunity;
  
  
  public PolicyServiceComponent() {
    ServiceBroker sb = new ServiceBrokerSupport();
    init(sb, null);
  }

  public PolicyServiceComponent(ServiceBroker sb, String community) {
    init(sb, community);
  }

  public ServiceBroker getServiceBroker() {
    return serviceBroker;
  }
  
  private void init(ServiceBroker sb, String community) {
    serviceBroker = sb;
    log = (LoggingService)serviceBroker.getService(this,LoggingService.class,null);
    mySecurityCommunity = community;
    registerServices();
  }
  
  private void registerServices() {
    if(log.isDebugEnabled()){
      log.debug("register services called on Policy Component");
    }
    isExecutedWithinNode = Boolean.valueOf(System.getProperty("org.cougaar.core.security.isExecutedWithinNode","false")).booleanValue();
    // Get root service broker
    if(isExecutedWithinNode){
      nodeControlService = (NodeControlService)
        serviceBroker.getService(this, NodeControlService.class, null);
      if (nodeControlService != null) {
        rootServiceBroker = nodeControlService.getRootServiceBroker();
        if (rootServiceBroker == null) {
          throw new RuntimeException("Unable to get root service broker");
        }
      }
    }
    else {
      // We are running outside a Cougaar node.
      // No Cougaar services are available.
      isExecutedWithinNode = false;
      rootServiceBroker = serviceBroker;
    }
    ServiceProvider newSP = null;
    if(log.isDebugEnabled()){
      log.debug("Creating Policy Service provider ");
    }
    services = SecurityServiceTable.getInstance(log);
    newSP = new PolicyServiceProvider(serviceBroker, mySecurityCommunity);
    services.put(PolicyService.class, newSP);
    rootServiceBroker.addService(PolicyService.class, newSP);
    if(log.isDebugEnabled()){
      log.debug("Added policy Service to root service broker ");
    }
    
  }
}
