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


package org.cougaar.core.security.policy.enforcers.init;

import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.policy.enforcers.SampleAgentEnforcer;
import org.cougaar.core.service.LoggingService;

public class InitAgentPlugin extends ComponentPlugin {

  private LoggingService _log;


    /*
     * This method does all the work of the TestEnforcer
     * (initialization).  The TestEnforcer is responsible for
     * initializing 
     *  1. a DummyNodeEnforcer component (which will eventually
     *     be adapted to a real enforcer)
     *  2. a SampleAgentEnforcer for each relevant agent.
     */
  protected void setupSubscriptions()
  {
    try {
	BindingSite bs = getBindingSite();
	ServiceBroker sb = bs.getServiceBroker();

        _log = (LoggingService) sb.getService(this,
                                              LoggingService.class,
                                              null);

	// Here is an agent of interest
	String agentName = getAgentIdentifier().toAddress();
        if (_log.isInfoEnabled()) {
          _log.info("Creating Enforcers for " + agentName);
        }

	// Every agent needs to be registered.  We do this by creating an 
	// agent enforcer for the agent and making sure that it is
	// registered.  It may be that this enforcer will play a more
	// real role later.
        getBlackboardService().closeTransactionDontReset();
        try {
	  (new SampleAgentEnforcer(sb, agentName)).registerEnforcer();
        }
        catch (Exception e) {
          if (_log.isWarnEnabled()) {
            _log.warn("Unable to register enforcer. InitAgentPlugin running without policy");
          }
        }
        getBlackboardService().openTransaction();
    } catch (Exception e) {
      _log.fatal(".InitAgentPlugin: Error initializing agent policy plugin",
                 e);
    }
  }

    /*
     * After setupSubscriptions there is really nothing for this
     * component to do.
     */
  protected void execute()
  {
    if (_log.isDebugEnabled()) {
      _log.debug("InitAgentPlugin.execute");
    }
  }
}
