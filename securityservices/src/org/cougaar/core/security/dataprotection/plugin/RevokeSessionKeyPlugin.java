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


import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.plugin.CompromiseBlackboard;
import org.cougaar.core.security.util.SharedDataRelay;
import org.cougaar.core.service.LoggingService;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;


/**
 * Listens for shared data relays containing tasks to revoke an agent's session
 * key stored on the blackboard after a time T. Theser are stored in
 * DataProtectionKeyContainers  on the Blackboard
 *
 * @author ttschampel
 */
public class RevokeSessionKeyPlugin extends ComponentPlugin {
  /** Plugin name */
  private static final String pluginName = "RevokeSessionKeyPlugin";
  /** Subscription to relays */
  private IncrementalSubscription relaySubs = null;
  /** Predicate for relays */
  private UnaryPredicate relayPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof SharedDataRelay) {
        SharedDataRelay sdr = (SharedDataRelay) o;
        if ((sdr.getContent() != null) && sdr.getContent() instanceof Task) {
          Task t = (Task) sdr.getContent();
          return (t.getVerb() != null) && t.getVerb().toString().equals(CompromiseBlackboard.REVOKE_SESSION_KEY_VERB);
        }
      }

      return false;
    }
  };

  /** Logging Service */
  private LoggingService logging = null;

  /**
   * UnaryPredicate for DP Key Container
   *
   * @param agent DOCUMENT ME!
   * @param timestamp DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   */
  private UnaryPredicate getCompromisedProtectionKeys(final String agent, final long timestamp) {
    return new UnaryPredicate() {
        public boolean execute(Object o) {
          if (o instanceof DataProtectionKeyContainer) {
            DataProtectionKeyContainer container = (DataProtectionKeyContainer) o;
            return (container.getAgentName() != null) && container.getAgentName().equals(agent) && (container.getTimestamp() >= timestamp);
          }

          return false;
        }
      };
  }


  /**
   * Populate LoggingService
   *
   * @param s LoggingService
   */
  public void setLoggingService(LoggingService s) {
    this.logging = s;
  }


  /**
   * Setup subsriptions
   */
  protected void setupSubscriptions() {
    this.relaySubs = (IncrementalSubscription) getBlackboardService().subscribe(this.relayPredicate);
    if (logging.isDebugEnabled()) {
      logging.debug(pluginName + " done with setup");
    }
  }


  /**
   * Process subscritpions
   */
  protected void execute() {
    if (logging.isDebugEnabled()) {
      logging.debug(pluginName + " executing");

    }

    processRelays();
  }


  private void processRelays() {
    Enumeration enumeration = this.relaySubs.getAddedList();
    while (enumeration.hasMoreElements()) {
      SharedDataRelay sdr = (SharedDataRelay) enumeration.nextElement();
      Task task = (Task) sdr.getContent();
      if (logging.isDebugEnabled()) {
        logging.debug("Got relay and task to revoke session key:" + task);
      }

      String agentName = (String) task.getPrepositionalPhrase(CompromiseBlackboard.FOR_AGENT_PREP).getIndirectObject();
      long compromiseTimestamp = ((Long) task.getPrepositionalPhrase(CompromiseBlackboard.COMPROMISE_TIMESTAMP_PREP).getIndirectObject()).longValue();
      if (logging.isDebugEnabled()) {
        logging.debug("Revoke session keys for " + agentName + " after " + new Date(compromiseTimestamp));
      }

      //get compromised session keys and revoke them
      Collection collection = getBlackboardService().query(getCompromisedProtectionKeys(agentName, compromiseTimestamp));
      Iterator iterator = collection.iterator();
      while (iterator.hasNext()) {
		DataProtectionKeyContainer dpk =(DataProtectionKeyContainer)iterator.next();
      	if(logging.isDebugEnabled()){
      		logging.debug("Removing session key for " + dpk.getAgentName() + ":" + new Date(dpk.getTimestamp()));
      	}
        getBlackboardService().publishRemove(dpk);
      }

      sdr.updateResponse(sdr.getSource(), task);
      getBlackboardService().publishChange(sdr);
    }
  }
}
