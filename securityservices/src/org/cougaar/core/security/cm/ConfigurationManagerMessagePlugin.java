/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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


package org.cougaar.core.security.cm;


import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.cm.message.VerifyAgentAddRequest;
import org.cougaar.core.security.cm.message.VerifyResponse;
import org.cougaar.core.security.cm.relay.SharedDataRelay;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;


/**
 * Listens For Messages from other Entities.  For now , the society
 * configuration is on the blackboard
 *
 * @author ttschampel
 * @version $Revision: 1.3 $
 */
public class ConfigurationManagerMessagePlugin extends ComponentPlugin {
  private static final String PLUGIN_NAME = "ConfigurationManagerMessagePlugin";
  private static UnaryPredicate relayPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        return o instanceof SharedDataRelay
        && ((SharedDataRelay) o).getContent() instanceof CMMessage;
      }
    };

  private IncrementalSubscription relaySubscription;
  private LoggingService logging;

  /**
   * Set logging service
   *
   * @param service Logging Service
   */
  public void setLoggingService(LoggingService service) {
    this.logging = service;
  }


  /**
   * Setup subscriptions
   */
  public void setupSubscriptions() {
    relaySubscription = (IncrementalSubscription) getBlackboardService()
                                                    .subscribe(relayPredicate);
  }


  /**
   * Execute subscriptions
   */
  public void execute() {
    handleVerifyRequests();
  }


  /**
   *
   */
  private void handleVerifyRequests() {
    Iterator i = relaySubscription.getAddedCollection().iterator();
    while (i.hasNext()) {
      SharedDataRelay relay = (SharedDataRelay) i.next();
      if (logging.isDebugEnabled()) {
        logging.debug(ConfigurationManagerMessagePlugin.PLUGIN_NAME
          + " Added Relay " + relay);
      }

      CMMessage cmMessage = (CMMessage) relay.getContent();
      if (cmMessage.getRequest() instanceof VerifyAgentAddRequest) {
        processVerifyAddAgentRequest(relay, cmMessage);
      }
    }
  }


  private void processVerifyAddAgentRequest(SharedDataRelay relay,
    CMMessage cmMessage) {
    VerifyResponse response = null;
    VerifyAgentAddRequest request = (VerifyAgentAddRequest) cmMessage
      .getRequest();
    String agent = request.getAgent();
    String node = request.getAddToNode();
    if (logging.isDebugEnabled()) {
      logging.debug(PLUGIN_NAME + " received add verify for " + agent
        + " to node" + node);
    }

    SocietyConfiguration sc = getSocietyConfiguration();
    if (sc != null) {
      HashMap agents = sc.getAgentConfigurations();
      Object object = agents.get(agent);
      boolean valid = false;
      if (object != null) {
        AgentConfiguration config = (AgentConfiguration) object;
        String agentType = config.getAgentType();
        if(logging.isDebugEnabled()){
        	logging.debug("Checking that " + node + " has facet role of " + agentType);
        	
        }
        HashMap nodeMap = sc.getNodeConfigurations();
        Object nodeObj = nodeMap.get(node);
        if(nodeObj!=null){
        	NodeConfiguration nc = (NodeConfiguration)nodeObj;
        	String nodeType  = 	nc.getNodeType();
        	if(logging.isDebugEnabled()){
        		logging.debug("Node role is " + nodeType + " and needed type is " + agentType);
        		
        	}
        	if(nodeType.equals(agentType)){
        		valid=true;
        	}
        }
        
      }else{
      	//if node configuration does not exist both are
      	//low security so allow it
      	HashMap nodeMap = sc.getNodeConfigurations();
      	Object nodeObj = nodeMap.get(node);
      	if(nodeObj==null){
      		valid = true;
      	}
      }

      response = new VerifyResponse(valid);
      cmMessage.setResponse(response);
    } else {
      if (logging.isWarnEnabled()) {
        logging.warn("Society configuration not found");
      }

      response = new VerifyResponse(false);
      cmMessage.setResponse(response);
    }


    relay.updateResponse(relay.getSource(), cmMessage);
    getBlackboardService().publishChange(relay);
  }


  private SocietyConfiguration getSocietyConfiguration() {
    SocietyConfiguration sc = null;
    Collection coll = getBlackboardService().query(new UnaryPredicate() {
          public boolean execute(Object o) {
            return o instanceof SocietyConfiguration;
          }
        });

    Iterator iter = coll.iterator();
    int index = 0;
    while (iter.hasNext()) {
      sc = (SocietyConfiguration) iter.next();
      index++;
    }

    if (index > 1) {
      if (logging.isWarnEnabled()) {
        logging.warn("More than 1 society configuration found!");
      }
    }

    return sc;
  }
}
