/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */

package org.cougaar.core.security.provider;

import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.crl.CrlManagement;
import org.cougaar.core.security.services.crypto.CrlManagementService;
import org.cougaar.planning.ldm.LDMServesPlugin;

public class  CrlManagementServiceProvider
  extends BaseSecurityServiceProvider  {
  
  static private CrlManagementService crlmgmtService;
  private LDMServesPlugin ldm;
  public  CrlManagementServiceProvider( LDMServesPlugin Ldm,ServiceBroker sb, String community) {
    super(sb, community);
    this.ldm=Ldm;
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
    // Implemented as a singleton service
    if (crlmgmtService == null) {
      try {
	crlmgmtService = new CrlManagement(ldm);
      }
      catch (Exception e) {
	boolean exec =
	  Boolean.valueOf(System.getProperty("org.cougaar.core.security.isExecutedWithinNode")).booleanValue();
	if (exec == true) {
	  log.warn("Unable to initialize Crl management  Service: ", e);
	}
	else {
	  log.info("Unable to initialize Crl management : " + e);
	}
      }
    }
    return crlmgmtService;
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
