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
import org.cougaar.core.security.certauthority.KeyManagement;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.CertificateManagementServiceClient;
import org.cougaar.core.security.services.crypto.KeyRingService;

import java.util.Hashtable;

public class CertificateManagementServiceProvider 
  extends BaseSecurityServiceProvider
{
  private KeyRingService ksr;
  private Hashtable cmsTable;

  public CertificateManagementServiceProvider(ServiceBroker sb, String community) {
    super(sb, community);
    cmsTable = new Hashtable();
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
    CertificateManagementService cms = null;
    if (requestor instanceof CertificateManagementServiceClient) {
      String caDN = ((CertificateManagementServiceClient)requestor).getCaDN();
      if (caDN == null) {
	// A standard node agent having signing authority
	caDN = "";
      }
      cms = (CertificateManagementService)cmsTable.get(caDN);
      if (log.isDebugEnabled()) {
	log.debug("Request CertificateManagementService for " + caDN
	  + " - cms in hashtable: " + cms);
      }
      if (cms == null) {
	try {
	  cms = new KeyManagement(sb);
	  ((KeyManagement)cms).setParameters(caDN);
	  cmsTable.put(caDN, cms);
	}
	catch (Exception e) {
	  cms = null;
	  if (log.isErrorEnabled()) {
	    log.error("Unable to initialize Key Management");
	  }
	}
      }
    }
    else {
      if (log.isErrorEnabled()) {
	log.error("Requestor is not a CertificateManagementServiceClient - Client type:"
		  + requestor.getClass().getName());
      }
      throw new RuntimeException("Requestor is not a CertificateManagementServiceClient:"
				 + requestor.getClass().getName());
    }
    return cms;
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
