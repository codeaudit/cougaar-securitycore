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

// Cougaar core infrastructure
import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.blackboard.CACertDirectoryServiceImpl;
import org.cougaar.core.security.naming.CertDirectoryServiceFactory;
import org.cougaar.core.security.naming.CertificateSearchServiceImpl;
import org.cougaar.core.security.services.util.CACertDirectoryService;
import org.cougaar.core.security.services.util.CertificateSearchService;

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
