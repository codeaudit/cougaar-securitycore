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

package org.cougaar.core.security.provider.policy;

import java.util.HashMap;

import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.access.message.MessageAccess;
import org.cougaar.core.security.policy.OwlMessageAccessPolicyServiceImpl;
import org.cougaar.core.security.policy.PolicyClient;
import org.cougaar.core.security.policy.XmlMessageAccessPolicyServiceImpl;
import org.cougaar.core.security.provider.BaseSecurityServiceProvider;
import org.cougaar.core.security.services.policy.PolicyService;
import org.cougaar.core.service.LoggingService;

public class PolicyServiceProvider extends BaseSecurityServiceProvider {
  
  private HashMap agentList = new HashMap();
  private LoggingService log ;

  public PolicyServiceProvider(ServiceBroker sb, String community) {
    super(sb, community);
    log = (LoggingService)sb.getService(this,LoggingService.class,null);
  }

  /* (non-Javadoc)
   * @see org.cougaar.core.security.provider.BaseSecurityServiceProvider#getInternalService(null, java.lang.Object, java.lang.Class)
   */
  protected Service getInternalService( ServiceBroker sb, Object requestor,
                                        Class serviceClass ) {
    String name;
    if(log.isDebugEnabled()){
      log.debug("getservice called with requestor "+ requestor.getClass().getName());
    }
    if(requestor instanceof PolicyClient){
      if(log.isDebugEnabled()){
        log.debug("requestor instance of Policy client "+ requestor.getClass().getName());
      }
    }
    else {
      if(log.isDebugEnabled()){
        log.debug("requestor NOT instance of Policy client "+ requestor.getClass().getName());
      }
    }
    if(!(requestor instanceof PolicyClient)){
      log.error("Only PolicyClient is allowed to request for the service.");
      return null;
    }
    Object service= null;
    if(requestor instanceof MessageAccess ){
      if(log.isDebugEnabled()){
        log.debug("requestor instance of message Access "+ requestor.getClass().getName());
      }
      if(agentList.containsKey("org.cougaar.core.security.access.message.MessageAccess")){
        service = agentList.get("org.cougaar.core.security.access.message.MessageAccess");
      }
      else {
        
        service = createMessageAccessService(sb);
        
      }
    }
    return (Service)service;
  }
    
  private Object createMessageAccessService(ServiceBroker sb){
    //, Vector policyservice){
    Object o= null;
    if(PolicyService.USE_DAML){
      if(log.isDebugEnabled()){
        log.debug("Creating Policy service for message access  with daml" );
      }
      o=new OwlMessageAccessPolicyServiceImpl(sb);
    }
    else {
      if(log.isDebugEnabled()){
        log.debug("Creating Policy service for message access  with XML" );
      }
      o=new XmlMessageAccessPolicyServiceImpl(sb);
    }
    //policyservice.add(new PolicyServiceMapping("org.cougaar.core.security.access.message.MessageAccess",o));
    //agentList.put(name,policyservice);
    agentList.put("org.cougaar.core.security.access.message.MessageAccess",o);
    return o;
  }
  
  
  /* (non-Javadoc)
   * @see org.cougaar.core.security.provider.BaseSecurityServiceProvider#releaseInternalService(null, java.lang.Object, java.lang.Class, java.lang.Object)
   */
  protected void releaseInternalService( ServiceBroker sb, Object requestor,
                                         Class serviceClass, Object service ) {
    String name = null;
    try {
      PolicyClient apc = (PolicyClient)requestor;
      name = apc.getName();
    } catch(Exception e) {
      log.error("Unable to release service:" + e);
    }
    if (name!=null) {
      agentList.remove(name);
    }
  }
  
}
