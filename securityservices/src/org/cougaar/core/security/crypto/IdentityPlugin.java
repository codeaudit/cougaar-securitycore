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


package org.cougaar.core.security.crypto;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.identity.AgentIdentityClient;
import org.cougaar.core.service.identity.AgentIdentityService;
import org.cougaar.core.service.identity.CrlReason;

import java.security.Principal;

import javax.security.auth.x500.X500Principal;

// Cougaar security services

public class IdentityPlugin
  extends ComponentPlugin
{
  private AgentIdentityService ais;
  private AgentIdentificationService agentIdentification;
  private String agentName;
  private LoggingService log;

  private String getAgentName() {
    return agentName;
  }

  private void acquireIdentity() {
    log.debug("ACQUIRE IDENTITY");
    agentIdentification = (AgentIdentificationService)
      getServiceBroker().getService(this,
				    AgentIdentificationService.class, null);
    agentName = agentIdentification.getName();

    try {
      X500Principal p = new X500Principal("CN="+getAgentName());
      ais = (AgentIdentityService)
	getServiceBroker().getService(new AgentIdentityClientImpl(p),
				      AgentIdentityService.class, null);
      ais.acquire(null);
    }
    catch (Exception e) {
      log.debug("Unable to get agent identity service", e);
    }
  }

  protected void setupSubscriptions() {
    log = (LoggingService)
      getServiceBroker().getService(this,
			       LoggingService.class, null);
    acquireIdentity();
  }

  protected void execute () {
  }

  private class AgentIdentityClientImpl
    implements AgentIdentityClient {
    private Principal principal;

    public AgentIdentityClientImpl(Principal p) {
      principal = p;
    }

    // AgentIdentityClient implementation
    public void identityRevoked(CrlReason reason) {
    }

    public String getName() {
      if (log.isDebugEnabled()) {
	log.debug("Creating key pair for "
			   + principal.getName());
      }
      return principal.getName();
    }
  }

}
