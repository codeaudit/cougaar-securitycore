/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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
 */

package org.cougaar.core.security.policy.enforcers.init;

import org.cougaar.core.security.policy.enforcers.SampleAgentEnforcer;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.util.*;

import kaos.core.service.directory.DefaultKAoSAgentDescription;
import kaos.core.service.directory.KAoSAgentDescription;
import kaos.core.service.directory.KAoSAgentDirectoryServiceProxy;
import kaos.core.service.util.cougaar.CougaarLocator;
import kaos.core.util.VMIDGenerator;
import kaos.ontology.jena.ActorConcepts;
import kaos.ontology.management.UnknownConceptException;

import safe.util.CougaarServiceRoot;

import org.cougaar.core.blackboard.*;
import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.*;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ServletService;
import org.cougaar.planning.ldm.policy.*;
import org.cougaar.util.*;

import org.cougaar.core.security.policy.EnforcerRegistrationException;

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
	_log.info("Creating Enforcers for " + agentName);

	// Every agent needs to be registered.  We do this by creating an 
	// agent enforcer for the agent and making sure that it is
	// registered.  It may be that this enforcer will play a more
	// real role later.
        getBlackboardService().closeTransactionDontReset();        
	(new SampleAgentEnforcer(sb, agentName)).registerEnforcer();
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
    _log.debug("InitAgentPlugin.execute");
  }
}
