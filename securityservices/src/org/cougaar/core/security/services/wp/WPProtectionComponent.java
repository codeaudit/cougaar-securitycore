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


package org.cougaar.core.security.services.wp;


import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.Component;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceProvider;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.node.NodeControlService;
import org.cougaar.core.security.services.wp.WhitePagesProtectionServiceImpl;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.wp.WhitePagesProtectionService;
import org.cougaar.util.GenericStateModelAdapter;


/**
 * Advertives the <code>WhitePagesProtectionService</code> in the root
 * <code>ServiceBroker</code>  Add to each node using:
 * Node.AgentManager.Agent.WPProtect(HIGH) =
 * org.cougaar.core.security.access.WPProtectionComponent
 *
 * @author mabrams
 */
public class WPProtectionComponent extends GenericStateModelAdapter implements Component {
  private ServiceBroker sb;
  private ServiceBroker rootsb;
  private LoggingService logger;
  private MessageAddress agentId;
  private WhitePagesProtectionService proxyWP;
  private ProtectSP protectSP;

  /**
   * sets the binding site
   *
   * @param bs the <code>BindingSite</code>
   */
  public void setBindingSite(BindingSite bs) {
    this.sb = bs.getServiceBroker();
  }


  /**
   * sets the logging service
   *
   * @param logger the <code>LoggingService</code>
   */
  public void setLoggingService(LoggingService logger) {
    this.logger = logger;
  }


  /**
   * Advertises the <code>WhitePagesProtectionService</code> in the root
   * <code>ServiceBroker</code> since the WPServer can be configured to run in
   * a regular agent instead of the NodeAgent.
   *
   * @throws RuntimeException
   */
  public void load() {
    super.load();

    if (logger.isDebugEnabled()) {
      logger.debug("Loading test protect");
    }

    // get the node-level service broker
    NodeControlService ncs = (NodeControlService) sb.getService(this, NodeControlService.class, null);
    if (ncs == null) {
      throw new RuntimeException("NodeControlService is null");
    }

    sb.releaseService(this, NodeControlService.class, ncs);
    rootsb = ncs.getRootServiceBroker();

    // which agent are we in?
    AgentIdentificationService ais = (AgentIdentificationService) sb.getService(this, AgentIdentificationService.class, null);
    agentId = ais.getMessageAddress();
    sb.releaseService(this, AgentIdentificationService.class, ais);

    // advertize our service
    protectSP = new ProtectSP();
    rootsb.addService(WhitePagesProtectionService.class, protectSP);

    if (logger.isInfoEnabled()) {
      logger.info("Loaded white pages protection service");
    }
  }


  /**
   * Unloads the <code>WhitePagesProtectionService</code>
   */
  public void unload() {
    super.unload();

    // revoke our service
    if (protectSP != null) {
      rootsb.revokeService(WhitePagesProtectionService.class, protectSP);
      protectSP = null;
    }

    if (logger != null) {
      sb.releaseService(this, LoggingService.class, logger);
      logger = null;
    }
  }

  private class ProtectSP implements ServiceProvider {
    WhitePagesProtectionServiceImpl impl = new WhitePagesProtectionServiceImpl(sb);

    public Object getService(ServiceBroker sb, Object requestor, Class serviceClass) {
      if (WhitePagesProtectionService.class.isAssignableFrom(serviceClass)) {
        return impl;
      } else {
        return null;
      }
    }


    public void releaseService(ServiceBroker sb, Object requestor, Class serviceClass, Object service) {
    }
  }
}
