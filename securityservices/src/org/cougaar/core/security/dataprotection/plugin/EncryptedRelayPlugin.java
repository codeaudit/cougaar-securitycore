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


package org.cougaar.core.security.dataprotection.plugin;


import java.util.Enumeration;
import java.security.MessageDigest;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.dataprotection.DataProtectionKeyImpl;
import org.cougaar.core.security.dataprotection.DataProtectionKeyCollection;
import org.cougaar.core.security.util.SharedDataRelay;
import java.util.Collection;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.UIDService;
import org.cougaar.util.UnaryPredicate;


/**
 * Receives Encrypted keys through relay
 *
 * @author ttschampel
 */
public class EncryptedRelayPlugin extends ComponentPlugin {
  /** Plugin name */
  private static final String pluginName = "EncryptedRelayPlugin";
  /** Logging Service */
  private LoggingService logging = null;
  /** Subscription to Relay */
  private IncrementalSubscription subs = null;
  /** Predicate for relay */
  private UnaryPredicate predicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof SharedDataRelay) {
        SharedDataRelay sdr = (SharedDataRelay) o;
        return (sdr.getContent() != null) && sdr.getContent() instanceof DataProtectionKeyCollection;
      }

      return false;
    }
  };

  /** UIDService */
  UIDService uidService = null;

  /**
   * DOCUMENT ME!
   *
   * @param s DOCUMENT ME!
   */
  public void setLoggingService(LoggingService s) {
    logging = s;
  }


  /**
   * DOCUMENT ME!
   */
  public void load() {
    super.load();
    uidService = (UIDService) this.getServiceBroker().getService(this, UIDService.class, null);
  }


  /**
   * Setup subscriptions
   */
  protected void setupSubscriptions() {
    subs = (IncrementalSubscription) getBlackboardService().subscribe(predicate);

  }


  /**
   * Process subscription
   */
  protected void execute() {
    if (logging.isDebugEnabled()) {
      logging.debug(pluginName + " executing");
    }

    Enumeration enumeration = subs.getAddedList();
    while (enumeration.hasMoreElements()) {
      SharedDataRelay sdr = (SharedDataRelay) enumeration.nextElement();
      DataProtectionKeyCollection keyCollection = (DataProtectionKeyCollection) sdr.getContent();
      DataProtectionKeyImpl dpKey = (DataProtectionKeyImpl)
        keyCollection.get(0);
      String agent = sdr.getSource().getAddress();
      long timestamp = System.currentTimeMillis();
      if (logging.isDebugEnabled()) {
        logging.debug("Got data protection key from " + agent);
      }

      if (keyCollection.getSignature() != null) {
        try {
          MessageDigest dg = MessageDigest.getInstance(dpKey.getDigestAlg());
          dg.update(keyCollection.getSignature());
          DataProtectionKeyContainer container = new DataProtectionKeyContainer(
            agent, dg.digest(), timestamp);
          container.setUID(uidService.nextUID());
          getBlackboardService().publishAdd(container);
        } catch (Exception e) {
          if (logging.isWarnEnabled()) {
            logging.warn("Exception occurred when trying to publish to PM: ", e);
          }
        }
      }
      getBlackboardService().publishRemove(sdr);
    }
  }
}
