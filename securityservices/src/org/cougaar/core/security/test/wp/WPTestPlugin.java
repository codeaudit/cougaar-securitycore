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


package org.cougaar.core.security.test.wp;


import java.net.InetAddress;
import java.net.URI;
import java.util.Collection;
import java.util.Iterator;

import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.wp.AddressEntry;
import org.cougaar.core.service.wp.WhitePagesService;


/**
 * Test Plugin.  Will take parameter, should be "BAD" or "GOOD" Bad  = this
 * plugin will try to bind a fake agent "FAKEAGENT" to the WP. Good = this
 * plugin will try to rebind itself normally.
 *
 * @author ttschampel
 */
public class WPTestPlugin extends ComponentPlugin {
  private LoggingService logging;
  boolean good = false;
  private WhitePagesService wp;

  /**
   * Set Logging Service
   *
   * @param s LogginService
   */
  public void setLoggingService(LoggingService s) {
    this.logging = s;

  }


  /**
   * Get parameter
   */
  public void load() {
    super.load();
    Collection parameters = this.getParameters();
    Iterator iterator = parameters.iterator();
    if (iterator.hasNext()) {
      String parameter = (String) iterator.next();
      if (parameter.toUpperCase().equals("GOOD")) {
        good = true;
      }
    } else {
      if (logging.isWarnEnabled()) {
        logging.warn("WPTestPlugin has not parameter, so will act as malicious plugin");
      }
    }

    if (logging.isDebugEnabled()) {
      logging.debug("WPTEstPlugin acting as a Legitimate Plugin:" + good);
    }
  }


  /**
   * Sets the WhitePagesService
   *
   * @param s WhitePagesService
   */
  public void setWhitePagesService(WhitePagesService s) {
    this.wp = s;

  }


  /**
   * Just get info from wp of other agent, then try to rebind my entry in wp.
   */
  protected void setupSubscriptions() {
    if (logging.isDebugEnabled()) {
      logging.debug("Setting up WPTestPlugin");
    }

    AddressEntry addressEntry = null;
    long timeout = 100000;

    //try to rebind as self
    try {
      InetAddress localAddr = InetAddress.getLocalHost();
      String localHost = localAddr.getHostName();
      NodeIdentificationService nodeIdService = (NodeIdentificationService) this.getServiceBroker().getService(this, NodeIdentificationService.class, null);

      URI nodeURI = null;
      nodeURI = URI.create("node://" + localHost + "/" + nodeIdService.getMessageAddress().getAddress());

      AddressEntry nodeEntry = null;
      if (good) {
        nodeEntry = AddressEntry.getAddressEntry(this.getAgentIdentifier().getAddress(), "topology", nodeURI);
        if (logging.isDebugEnabled()) {
          logging.debug("Trying to rebind agent to same location");
        }
      } else {
        //try to re-bind ca agent here
        if (logging.isDebugEnabled()) {
          logging.debug("Trying to rebind the caAgent to this node");
        }

        nodeEntry = AddressEntry.getAddressEntry("caAgent", "topology", nodeURI);
      }

      wp.rebind(addressEntry, timeout);
    } catch (Exception exception) {
      if (logging.isErrorEnabled()) {
        logging.error("Error rebinding ", exception);
      }
    }
  }


  /**
   * Blank implementation
   */
  protected void execute() {
  }
}
