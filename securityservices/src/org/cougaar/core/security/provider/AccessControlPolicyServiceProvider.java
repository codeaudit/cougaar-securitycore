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

import java.util.HashMap;

import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.access.AccessControlPolicyServiceImpl;
import org.cougaar.core.security.access.AccessPolicyClient;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

public class AccessControlPolicyServiceProvider 
  extends BaseSecurityServiceProvider
{
  private KeyRingService keyRing;
  private SecurityPropertiesService sps;
  private HashMap agentList = new HashMap();

  public AccessControlPolicyServiceProvider(ServiceBroker sb, String community) {
    super(sb, community);
  }

  /**
   * Get a service.
   * @param sb a Service Broker
   * @param requestor the requestor of the service
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @return a service
   */
  protected synchronized Service getInternalService(ServiceBroker sb, 
						    Object requestor, 
						    Class serviceClass) {
    String name;
    try {
      AccessPolicyClient apc = (AccessPolicyClient)requestor;
      name = apc.getName();
    } catch(Exception e) {
      //the cast failed, not an access agent binder, no service.
      log.error("Only AccessPolicyClient is allowed to request for the service.");
      return null;
    }
    Object o = agentList.get(name);
    if (o == null) {
      o = new AccessControlPolicyServiceImpl(serviceBroker, name);
      agentList.put(name, o);
    }
    if (log.isDebugEnabled()) {
      log.debug("AC policy Service Request: "
		+ requestor.getClass().getName()
		+ " - " + serviceClass.getName());
    }

    return (Service)o;
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
    String name = null;
    try {
      AccessPolicyClient apc = (AccessPolicyClient)requestor;
      name = apc.getName();
    } catch(Exception e) {
      log.error("Unable to release service:" + e);
    }
    if (name!=null) {
      agentList.remove(name);
    }
  }
}
