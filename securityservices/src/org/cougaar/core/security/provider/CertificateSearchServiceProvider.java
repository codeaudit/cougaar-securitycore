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

// Cougaar core infrastructure
import org.cougaar.core.component.*;
import org.cougaar.util.*;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.naming.*;
import org.cougaar.core.security.crypto.blackboard.CACertDirectoryServiceImpl;
import org.cougaar.core.security.naming.CertificateEntry;

public class CertificateSearchServiceProvider
  extends BaseSecurityServiceProvider {

  static private CertificateSearchService _searchService = null;
  static private CACertDirectoryService _caService = null;

  public CertificateSearchServiceProvider(ServiceBroker sb, String community) {
    super(sb, community);
  }

  /**
   * Get a service.
   * @param sb a Service Broker
   * @param requestor the requestor of the service
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @return a service
   */
  protected Service getInternalService(ServiceBroker sb,
				       Object requestor,
				       Class serviceClass) {
    Service serv = null;

    if (serviceClass.equals(CertificateSearchService.class)) {
      if (_searchService != null) {
	serv = _searchService;
      }
      try {
	_searchService = new CertificateSearchServiceImpl(sb, new CertDirectoryServiceFactory(sb));
	serv = _searchService;
      }
      catch (Exception e) {
	log.debug("Failed to initialize CertificateSearchServiceImpl! " + e.toString(), e);
      }
    }
    else if (serviceClass.equals(CACertDirectoryService.class)) {
      if (_caService != null) {
	serv = _caService;
      }
      try {
	_caService = new CACertDirectoryServiceImpl(sb);
	serv = _caService;
      }
      catch (Exception e) {
	log.debug("Failed to initialize CACertDirectoryService! " + e.toString(), e);
      }
    }
    return serv;
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
