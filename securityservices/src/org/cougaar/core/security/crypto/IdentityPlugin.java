/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 * Created on March 18, 2002, 2:42 PM
 */

package org.cougaar.core.security.crypto;

import java.security.Principal;
import javax.security.auth.x500.X500Principal;

// Cougaar core services
import org.cougaar.core.service.identity.*;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.*;

// Cougaar security services
import org.cougaar.core.security.util.CryptoDebug;

public class IdentityPlugin
  extends ComponentPlugin
{
  private AgentIdentityService ais;
  private AgentIdentificationService agentIdentification;
  private String agentName;

  private String getAgentName() {
    return agentName;
  }

  private void acquireIdentity() {
    System.out.println("ACQUIRE IDENTITY");
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
      System.out.println("Unable to get agent identity service: "
			 + e);
      e.printStackTrace();
    }
  }

  protected void setupSubscriptions() {
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
      if (CryptoDebug.debug) {
	System.out.println("Creating key pair for "
			   + principal.getName());
      }
      return principal.getName();
    }
  }

}
