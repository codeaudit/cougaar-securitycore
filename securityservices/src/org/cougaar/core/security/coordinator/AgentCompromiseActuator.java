/*
 * <copyright>
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA)
 *  and the Defense Logistics Agency (DLA).
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

package org.cougaar.core.security.coordinator;

import org.cougaar.coordinator.*;
import org.cougaar.coordinator.techspec.TechSpecNotFoundException;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;

import java.util.Set;
import java.util.HashSet;
import java.util.Iterator;

public class AgentCompromiseActuator extends ComponentPlugin
{
  private LoggingService log;
  private AgentCompromiseAction action;
  private ServiceBroker sb;
  private IncrementalSubscription actionSub;

  private UnaryPredicate actionPred = new UnaryPredicate() {
            public boolean execute(Object o) {
                return (o instanceof AgentCompromiseAction);}};

  public void load() {
    super.load();

    sb = getServiceBroker();
    log = (LoggingService)
            sb.getService(this, LoggingService.class, null);

  }

  public synchronized void unload() {
  }

  public void setupSubscriptions()
  {
    actionSub = (IncrementalSubscription)blackboard.subscribe(actionPred);
  }

  boolean start = true;
  int tsLookupCnt = 0;
  public synchronized void execute() {
    if (start) { 
      try {
        Set values = new HashSet();
        values.add(AgentCompromiseAction.RESTART);
        values.add(AgentCompromiseAction.DONOTHING);
        AgentCompromiseAction action = new AgentCompromiseAction(agentId.toString(), values, sb);
        blackboard.publishAdd(action);
        if (log.isDebugEnabled()) log.debug(action+" added.");
        start = false;
      } catch (TechSpecNotFoundException e) {
        if (tsLookupCnt > 10) {
          log.warn("TechSpec not found for SampleAction.  Will retry.", e);
          tsLookupCnt = 0;
        }
        blackboard.signalClientActivity();
      } catch (IllegalValueException ive) {
        log.error("Exception for initialization: " + ive);
      }
      
    }

    Iterator iter = actionSub.getChangedCollection().iterator();
    while (iter.hasNext()) {
      AgentCompromiseAction action = (AgentCompromiseAction)iter.next();
      if (action != null) {
        if (log.isDebugEnabled()) {
          log.debug("received action: " + action);
        }

        Set newPV = action.getPermittedValues(); 
        if (newPV != null) {
          if (newPV.size() != 1) {
            log.warn("More than one possible action value. Action will not be performed");
            break;
          }

          Iterator values = newPV.iterator();
          String value = (String)values.next();
          if (value.equals(AgentCompromiseAction.RESTART)) {
            try {
              action.start(value);
              blackboard.publishChange(action);
                        if (log.isDebugEnabled())
                            log.debug(action + " started.");
              // TODO do the handling action here

              action.stop(Action.COMPLETED);
              blackboard.publishChange(action);
                        if (log.isDebugEnabled())
                            log.debug(action + " stopped.");
            } catch (IllegalValueException e) {
              log.error("Illegal actionValue = "+value,e);
              break;
            } catch (NoStartedActionException nsae) {} // not going to happen

          }
          // else do nothing
        }
      }
    }
  }
}

