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
