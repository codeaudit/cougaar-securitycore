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

import org.cougaar.community.CommunityProtectionService;
import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.enforcers.CommunityProtectionServiceImpl;
import org.cougaar.core.service.LoggingService;

public class CommunityProtectionServiceProvider
  extends BaseSecurityServiceProvider
{
  static private CommunityProtectionService _cps;
  private LoggingService _log;

  public CommunityProtectionServiceProvider(ServiceBroker sb, String community) 
  {
    super(sb, community);
    _log = (LoggingService) sb.getService(this, LoggingService.class, null);
    if (_log.isDebugEnabled()) {
      _log.debug("Constructing the Commmunity Service Protection Service Provider");
    }
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
						    Class serviceClass) 
  {
    if (_cps == null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Construction the implementation of the Commmunity Protection Service");
      }

      _cps = new CommunityProtectionServiceImpl(sb);
    }
    return _cps;
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