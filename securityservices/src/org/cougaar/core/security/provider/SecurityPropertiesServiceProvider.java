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

import java.util.Hashtable;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;

import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.util.SecurityPropertiesServiceImpl;

public class SecurityPropertiesServiceProvider
  extends BaseSecurityServiceProvider
{
  /** A hashtable containing all the servlet context instances */
  static private Hashtable contextMap;
  /** A singleton service to use when servlet context is null. */
  static private SecurityPropertiesService secProp;

  public SecurityPropertiesServiceProvider(ServiceBroker sb, String community) {
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
    SecurityPropertiesService securityPropertiesService = null;
    // Instantiate one service for each servlet context
    javax.servlet.ServletContext context = null;

    if (requestor instanceof Servlet) {
      Servlet servlet = (Servlet) requestor;
      ServletConfig config = servlet.getServletConfig();
      if (config != null) {
	context = config.getServletContext();
      }
    }
    if (context == null) {
      if (secProp == null) {
	secProp = new SecurityPropertiesServiceImpl(sb);
      }
      securityPropertiesService = secProp;
    }
    else {
      // Figure out if the service has already been instantiated
      // for that context.
      securityPropertiesService =
	(SecurityPropertiesService)contextMap.get(context);
      if (securityPropertiesService == null) {
	securityPropertiesService =
	  new SecurityPropertiesServiceImpl(context, sb);
	contextMap.put(context, securityPropertiesService);
      }
    }
    return securityPropertiesService;
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
