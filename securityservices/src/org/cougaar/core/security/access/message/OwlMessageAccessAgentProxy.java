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

import java.util.Set;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.MessageAccessPermission;
import org.cougaar.core.security.policy.mediator.PolicyMediator;
import org.cougaar.core.security.services.policy.PolicyService;
import org.cougaar.core.service.MessageTransportService;

public class OwlMessageAccessAgentProxy extends AccessAgentProxy {
    
  private PolicyMediator messageMediator;

  public OwlMessageAccessAgentProxy(MessageTransportService mymts, Object myobj ,
                                    PolicyService ps, ServiceBroker sb){
    super(mymts,myobj,ps,sb);
        
  }

  public Set getAllowedVerbs(String source, String target) {
    if(log.isDebugEnabled()){
      log.debug("getAllowedVerbs called ");
    }
    Set ret = null;
    if(this.messageMediator!= null) {
      if(log.isDebugEnabled()){
        log.debug("Message Mediator is not null calling getAllowedVerbs");
      }
      ret = messageMediator.getAllowedVerbs(source,target);
    }
    else {
      if(log.isDebugEnabled()){
        log.debug("Message Mediator is Null calling checkForMediator");
      }
      checkForMediator();
      if(this.messageMediator!= null) {
        ret = messageMediator.getAllowedVerbs(source,target);
      }
    }
    return ret;
  }

  public boolean isMessageDenied(String source, String target, String verb,
                                 boolean direction) {
    if(log.isDebugEnabled()){
      log.debug("is message denied called ");
    }
    boolean ret = false;
    if(this.messageMediator!= null) {
      if(log.isDebugEnabled()){
        log.debug("Message Mediator is not null calling checkMessagePermission");
      }
      ret = checkMessagePermission(source,target,verb);
    }
    else {
      if(log.isDebugEnabled()){
        log.debug("Message Mediator is Null calling checkForMediator");
      }
      checkForMediator();
      if(this.messageMediator!= null) {
        ret = checkMessagePermission(source,target,verb);
      }
    }
    return !ret;
       
  }
   
  private void checkForMediator(){
    if(policyService!=null){
      messageMediator= policyService.getPolicyMediator()  ;         
    }
  }
   
  /*
   * @return true - message allowed
   * 				false- message denied
   */
  private boolean checkMessagePermission(String source, String target, String verb){
    boolean ret = false;
    if(log.isDebugEnabled()){
      log.debug("checkMessagePermission called for Daml agent proxy ");
    }
    ret = messageMediator.checkPermision(new MessageAccessPermission(source,target,verb));
    if(log.isDebugEnabled()){
      log.debug("checkPermission from mediator returned "+ ret);
    }
    if(log.isDebugEnabled()){
      log.debug("isActionAuthorized returns " + ret);
    }
    return ret;
  }
    
   
}
