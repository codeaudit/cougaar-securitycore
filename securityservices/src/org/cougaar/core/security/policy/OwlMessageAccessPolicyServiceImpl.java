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

package org.cougaar.core.security.policy;

import java.security.Permission;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.mediator.PolicyMediator;
import org.cougaar.core.security.services.policy.PolicyService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


public class OwlMessageAccessPolicyServiceImpl implements PolicyService {
  
  private transient Logger log;
  private transient ServiceBroker serviceBroker;
  private PolicyMediator mediator= null;
  
  public OwlMessageAccessPolicyServiceImpl(ServiceBroker sb){
    serviceBroker = sb;
    log = (LoggingService)serviceBroker.getService(this,
                                                   LoggingService.class, null);
    if(log == null) {
      log = LoggerFactory.getInstance().createLogger(this);
    } 
    
  }

  /* (non-Javadoc)
   * @see org.cougaar.core.security.services.policy.PolicyService#registerMediator(org.cougaar.core.security.policy.mediator.PolicyMediator, java.lang.Class)
   */
  public void registerMediator(PolicyMediator msp ) {
    if(log.isDebugEnabled()){
      log.debug("Registering Policy mediator "+ msp.getName());
    }
    mediator = msp;
  }

  /* (non-Javadoc)
   * @see org.cougaar.core.security.services.policy.PolicyService#getPolicyMediator(java.lang.Class)
   */
  public PolicyMediator getPolicyMediator() {
    return mediator;
  }

  /* (non-Javadoc)
   * @see org.cougaar.core.security.services.policy.PolicyService#checkPermision(java.security.Permission)
   */
  public boolean checkPermision( Permission permisssion ) {
    if(mediator!=null){
      return mediator.checkPermision(permisssion);
    }
    return false;
  }

}
