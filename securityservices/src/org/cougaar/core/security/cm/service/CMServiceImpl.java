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


package org.cougaar.core.security.cm.service;


import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.cm.CMMessage;
import org.cougaar.core.security.cm.CMMessage.CMRequest;
import org.cougaar.core.security.cm.relay.SharedDataRelay;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.util.UID;


/**
 * Configuration Manager Service Implementation     For now use property to get
 * cm agent :     <b>(org.cougaar.core.security.cm.location)</b>
 *
 * @author ttschampel
 * @version $Revision: 1.1 $
 */
public class CMServiceImpl implements CMService {
  /** Logging Service */
  private LoggingService logging;
  /** Service Broker */
  private ServiceBroker serviceBroker;
  /** UIDService */
  private UIDService uidService;
  /** Agent Identification Service */
  private AgentIdentificationService agentIdService;

  /**
   * Creates a new CMService object.
   *
   * @param sb Service Broker used to get Cougaar Services
   */
  public CMServiceImpl(ServiceBroker sb) {
    serviceBroker = sb;
    load();
  }

  /**
   * Set the service broker
   *
   * @param sb ServiceBroker
   */
  public void setServiceBroker(ServiceBroker sb) {
    this.serviceBroker = sb;
  }


  /**
   * Load service
   */
  private void load() {
    logging = (LoggingService) serviceBroker.getService(this,
        LoggingService.class, null);


    uidService = (UIDService) serviceBroker.getService(this, UIDService.class,
        null);
    agentIdService = (AgentIdentificationService) serviceBroker.getService(this,
        AgentIdentificationService.class, null);
  }


  /**
   * Send a message to the configuration manager.  This should be called within
   * a BlackboardService Transaction.
   *
   * @param request CMRequest to send
   * @param bbs DOCUMENT ME!
   */
  public void sendMessage(CMRequest request, BlackboardService bbs) {
    //create shared data relay and publish to blackboard
    String cmAgentLocation = System.getProperty(
        "org.cougaar.core.security.cm.location");
    if (cmAgentLocation == null) {
      if (logging.isWarnEnabled()) {
        logging.warn("Configuration Manager location parameter is null");
      }
      return;
    }

    MessageAddress target = MessageAddress.getMessageAddress(cmAgentLocation);

    if (logging.isDebugEnabled()) {
      logging.debug("Sending CMRequest to " + target);
    }

    UID uid = uidService.nextUID();
    CMMessage content = new CMMessage();
    content.setRequest(request);
    Object response = null;
    MessageAddress source = agentIdService.getMessageAddress();
    SharedDataRelay relay = new SharedDataRelay(uid, source, target, content,
        response);
    bbs.publishAdd(relay);

  }
}
