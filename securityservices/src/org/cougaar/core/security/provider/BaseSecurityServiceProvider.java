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

import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceProvider;
import org.cougaar.core.service.LoggingService;

public abstract class BaseSecurityServiceProvider
  implements ServiceProvider
{
  protected LoggingService log;
  protected ServiceBroker serviceBroker;
  protected String mySecurityCommunity;

  public BaseSecurityServiceProvider(ServiceBroker sb, String community) {
    serviceBroker = sb;
    mySecurityCommunity = community;
    log = (LoggingService)
      sb.getService(this, LoggingService.class, null);
  }

  /** **********************************************************************
   * ServiceProvider Interface
   */
  public Object getService(ServiceBroker sb,
			   Object requestor,
			   Class serviceClass) {
    if (log.isDebugEnabled()) {
      log.debug("Security Service Request: "
		+ requestor.getClass().getName()
		+ " - " + serviceClass.getName());
    }
    if (sb == null) {
      if (log.isWarnEnabled()) {
	log.warn("Running in a test environment");
      }
      sb = serviceBroker;
    }
    SecurityManager security = System.getSecurityManager();
    if (serviceClass == null) {
      throw new IllegalArgumentException("Illegal service class");
    }
    if(security != null) {
      log.debug("Checking Security Permission for :"+serviceClass.getName()+
		"\nRequestor is "+requestor.getClass().getName());
      security.checkPermission(new SecurityServicePermission(serviceClass.getName()));
    }
    Service service = null;
    try {
      service = getInternalService(sb, requestor, serviceClass);
    }
    catch (Exception e) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to get service request for " + serviceClass.getName() + ": " , e);
      }
    }
    if (service == null) {
      if (log.isWarnEnabled()) {
	log.warn("Service not registered: " + serviceClass.getName()
	  + " Requestor:" + requestor.getClass().getName());
      }
    }
    return service;
  }

  public void releaseService(ServiceBroker sb,
			     Object requestor,
			     Class serviceClass,
			     Object service) {
    releaseInternalService(sb, requestor, serviceClass, service);
  }

  /** **********************************************************************
   * End ServiceProvider Interface
   */

  protected abstract Service getInternalService(ServiceBroker sb, 
						Object requestor, 
						Class serviceClass);

  protected abstract void releaseInternalService(ServiceBroker sb,
						 Object requestor,
						 Class serviceClass,
						 Object service);
}
