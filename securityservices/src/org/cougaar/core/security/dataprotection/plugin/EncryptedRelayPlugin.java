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



package org.cougaar.core.security.dataprotection.plugin;


import java.security.MessageDigest;
import java.util.Enumeration;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.dataprotection.DataProtectionKeyCollection;
import org.cougaar.core.security.dataprotection.DataProtectionKeyImpl;
import org.cougaar.core.security.util.SharedDataRelay;
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
          byte [] digest = dg.digest();

          if (logging.isDebugEnabled()) {
            logging.debug("signature ");
            byte [] sig = keyCollection.getSignature();
           
            KeyRecoveryRequestHandler.printBytes(sig, 0, 10, logging);

            logging.debug("timestamp " + timestamp + " vs " + keyCollection.getTimestamp());
          }

          DataProtectionKeyContainer container = new DataProtectionKeyContainer(
            agent, digest, timestamp);
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
