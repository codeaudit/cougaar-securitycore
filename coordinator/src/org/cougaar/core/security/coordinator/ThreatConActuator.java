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
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;

import java.util.Set;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Collection;

public class ThreatConActuator extends ComponentPlugin
{
  private LoggingService log;
  private ThreatConAction action;
  private ServiceBroker sb;
  private IncrementalSubscription actionSub;
  private IncrementalSubscription diagnosisSub;
  private IncrementalSubscription infoSub;

  private UnaryPredicate actionPred = new UnaryPredicate() {
            public boolean execute(Object o) {
                return (o instanceof ThreatConAction);
            }
  };

  private UnaryPredicate diagnosisPred = new UnaryPredicate() {
            public boolean execute(Object o) {
                return (o instanceof ThreatConDiagnosis);
            }
  };

  private UnaryPredicate infoPred = new UnaryPredicate() {
            public boolean execute(Object o) {
                if (o instanceof ThreatConActionInfo) {
                  return ((ThreatConActionInfo)o).getDiagnosis().equals(ThreatConActionInfo.ACTIVE);
                }
                return false;
            }
  };

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
    diagnosisSub = (IncrementalSubscription)blackboard.subscribe(diagnosisPred);
    infoSub = (IncrementalSubscription)blackboard.subscribe(infoPred);
  }

  int tsLookupCnt = 0;
  public synchronized void execute() {
    Collection c = diagnosisSub.getAddedCollection();
    if (c.size() != 0) {
      ThreatConDiagnosis diagnosis = (ThreatConDiagnosis)c.iterator().next();
      if (action != null) {
        log.warn("Action already published! New diagnosis " + diagnosis);
      }        
      else {
        String communityName = diagnosis.getAssetName();
      
        try {
          Set values = new HashSet();
          values.add(ThreatConActionInfo.LOW);
          values.add(ThreatConActionInfo.HIGH);
          action = new ThreatConAction(communityName, values, sb);
          blackboard.publishAdd(action);
          if (log.isDebugEnabled()) log.debug(action+" added.");
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
    }

    Iterator iter = actionSub.getChangedCollection().iterator();
    while (iter.hasNext()) {
      ThreatConAction action = (ThreatConAction)iter.next();
      if (action != null) {
        if (log.isDebugEnabled()) {
          log.debug("received action: " + action);
        }

        Set newPV = action.getNewPermittedValues(); 
          if (newPV.size() != 1) {
            log.warn("More than one possible action value. Action will not be performed");
            break;
          }

          Iterator values = newPV.iterator();
          String value = (String)values.next();
          try {
              action.start(value);
              blackboard.publishChange(action);
                        if (log.isDebugEnabled()) 
                            log.debug(action + " started.");
              ThreatConActionInfo info = new ThreatConActionInfo(action.getAssetName(), value);
              blackboard.publishAdd(info);
          } catch (IllegalValueException e) {
              log.error("Illegal action "+action,e);
              continue;
          }
      } // if
    } // while
  

    iter = infoSub.getChangedCollection().iterator();
    while (iter.hasNext()) {
      ThreatConActionInfo info = (ThreatConActionInfo)iter.next();

      if (action == null) {
        log.error("No action created yet!" + info);
        continue;
      }

      try {
        action.stop(Action.ACTIVE);
        blackboard.publishChange(action);
        if (log.isDebugEnabled()) 
          log.debug(action + " stopped.");
      } catch (IllegalValueException e) {
        log.error("Illegal action "+action,e);
        continue;
      } catch (NoStartedActionException nsae) {
        log.error("Not started action "+action,nsae);
        continue;
      }
      blackboard.publishRemove(info); 
    }
  }
}

