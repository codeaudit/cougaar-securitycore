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
import java.util.Hashtable;

public class AgentCompromiseActuator extends ComponentPlugin
{
  private LoggingService log;
  private AgentCompromiseAction action;
  private ServiceBroker sb;
  private IncrementalSubscription actionSub;
  private IncrementalSubscription diagnosisSub;
  private IncrementalSubscription infoSub;
  private Hashtable _agentCache = new Hashtable();

  private UnaryPredicate actionPred = new UnaryPredicate() {
    public boolean execute(Object o) {
      return (o instanceof AgentCompromiseAction);
    }
  };

  private UnaryPredicate diagnosisPred = new UnaryPredicate() {
    public boolean execute(Object o) {
      return (o instanceof AgentCompromiseDiagnosis);
    }
  };


  private UnaryPredicate infoPred = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof AgentCompromiseInfo) {
        return ((AgentCompromiseInfo)o).getType().equals(AgentCompromiseInfo.COMPLETION_CODE);
      }
      return false;
    }
  };

  private UnaryPredicate sensorPred = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof AgentCompromiseInfo) {
        return ((AgentCompromiseInfo)o).getType().equals(AgentCompromiseInfo.SENSOR);
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
      
    Iterator iter = actionSub.getChangedCollection().iterator();
    while (iter.hasNext()) {
      AgentCompromiseAction action = (AgentCompromiseAction)iter.next();
      if (action != null) {
        if (log.isDebugEnabled()) {
          log.debug("received action: " + action);
        }

        // check whether action has start or stopped
        ActionRecord lastAction = action.getValue();
        if (lastAction != null) {
          if (lastAction.getAction().equals(AgentCompromiseAction.RESTART)) {
            if (log.isDebugEnabled()) {
              log.debug("Ignoring action already in process.");
            }
            continue;
          }
        }

        Set newPV = action.getNewPermittedValues(); 
        if (newPV != null) {
          try {
            action.setPermittedValues(newPV);
          } catch (IllegalValueException ioe) {
            log.error("Illegal actionValue = "+action,ioe);
            continue;
          }
          if (newPV.size() == 0) {
            // it is not doing anything, just acknowledging some change
            if (log.isDebugEnabled()) {
              log.debug("Ignoring action with no value");
            }
            continue;
          }

          if (newPV.size() != 1) {
            log.warn("More than one possible action value. Action will not be performed: ");
            Iterator it = newPV.iterator();
            while (it.hasNext()) {
              String newAct = (String)it.next();
              log.warn("Action: " + newAct);
            }
            continue;
          }

          Iterator values = newPV.iterator();
          String value = (String)values.next();
          if (value.equals(AgentCompromiseAction.RESTART)) {
            // inform MnR to restart
            if (action.getCompromiseInfo() == null) {
              log.error("There is no info on the compromise for " + action);
              continue;
            }

            if (log.isDebugEnabled()) {
              log.debug("Listing Permitted values: ");
              Set permitted = action.getPermittedValues();
              Iterator it = permitted.iterator();
              while (it.hasNext()) {
                String act = (String)it.next();
                log.debug("Permitted: " + act);
              }
            }

            try {
              action.start(value);
              action.clearNewPermittedValues();
              blackboard.publishChange(action);
                        if (log.isDebugEnabled())
                            log.debug(action + " started.");
            } catch (IllegalValueException e) {
              log.error("Illegal actionValue = "+action,e);
              continue;
            } 

            action.getCompromiseInfo().setType(AgentCompromiseInfo.ACTION);
            blackboard.publishAdd(action.getCompromiseInfo());      
          }
          // else do nothing
          else {
            String agent = action.getAssetName();
            Iterator it = blackboard.query(sensorPred).iterator();
            while (it.hasNext()) {
              AgentCompromiseInfo info = (AgentCompromiseInfo)it.next();
              if (info.getSourceAgent().equals(agent)) {
                if (log.isDebugEnabled()) {
                  log.debug("Removing info for " + agent);
                }
                blackboard.publishRemove(info);
              }
            }

            if (log.isDebugEnabled()) {
              log.debug("DoNothing: " + action);
            }
            action.clearNewPermittedValues();
            blackboard.publishChange(action);
          }
        }
      }
    }

    // also publish action with new diagnosis
    iter = diagnosisSub.getAddedCollection().iterator();
    while (iter.hasNext()) {
      AgentCompromiseDiagnosis diagnosis = (AgentCompromiseDiagnosis)iter.next();
      String agent = diagnosis.getAssetName(); 
      publishAction(agent);
    }
    // remove action with diagnosis removed
    iter = diagnosisSub.getRemovedCollection().iterator();
    while (iter.hasNext()) {
      AgentCompromiseDiagnosis diagnosis = (AgentCompromiseDiagnosis)iter.next();
      String agent = diagnosis.getAssetName();
      AgentCompromiseAction action = (AgentCompromiseAction)_agentCache.get(agent);
      if (action == null) {
        log.error("Diagnosis removed for " + agent + " but action not found");
      }
      else {
        _agentCache.remove(agent);
        blackboard.publishRemove(action);
        if (log.isDebugEnabled()) {
          log.debug("Action for " + agent + " removed");
        }
      }
    } 
    // publish action with changed diagnosis
    iter = diagnosisSub.getChangedCollection().iterator();
    while (iter.hasNext()) {
      AgentCompromiseDiagnosis diagnosis = (AgentCompromiseDiagnosis)iter.next();
      String agent = diagnosis.getAssetName();
      AgentCompromiseAction action = (AgentCompromiseAction)_agentCache.get(agent);
      if (action == null) {
        log.error(agent + "action not found");
      }
      else {
        // offer restart if moderate or severe
        if (!((String)diagnosis.getValue()).equals(AgentCompromiseInfo.NONE)) {
          // setting to NONE is completion code, handled by infoSub
          try {
            Set values = new HashSet();
            values.add(AgentCompromiseAction.RESTART);
            values.add(AgentCompromiseAction.DONOTHING);
            action.setValuesOffered(values);
            action.setCompromiseInfo(diagnosis.getCompromiseInfo());
            blackboard.publishChange(action); 
            if (log.isDebugEnabled()) {
              log.debug("offered action for diagnosis: " + diagnosis);
            }
          } catch (IllegalValueException e) {
            log.error("Illegal actionValue = "+action,e);
            continue;
          }

        }
      }
    }

    iter = infoSub.getAddedCollection().iterator();
    while (iter.hasNext()) {
      AgentCompromiseInfo info = (AgentCompromiseInfo)iter.next();
      // clean up
      blackboard.publishRemove(info);
      AgentCompromiseAction action = (AgentCompromiseAction)_agentCache.get(info.getSourceAgent());
      if (action == null) {
        log.warn("There is no action associated with info: " + info);
        continue;
      }
      ActionRecord record = action.getValue();
      if (record.hasCompleted()) {
        if (log.isDebugEnabled()) {
          log.debug("Ignoring info for action already completed.");
        }
        continue;
      }

      if (log.isDebugEnabled()) {
        log.debug("Info " + info.getDiagnosis() + " for action." + action);
      }
      try {
        if (info.getDiagnosis().equals(AgentCompromiseInfo.FAILED)) {
          action.stop(Action.FAILED); 
        }
        // there is only two things can happen
        else {
          action.stop(Action.COMPLETED);
          Set values = new HashSet();
          values.add(AgentCompromiseAction.DONOTHING);
          action.setValuesOffered(values);
        }
        
        blackboard.publishChange(action);
        if (log.isDebugEnabled())
          log.debug(action + " stopped.");
      } catch (IllegalValueException e) {
        log.error("Illegal actionValue = "+action,e);
        continue;
      } catch (NoStartedActionException nsae) {
        log.error("action not started "+action,nsae);
      } 
    }
  }


  private void publishAction(String agent) {  
      if (log.isDebugEnabled()) {
        log.debug("publishing action for " + agent);
      }
      try {
        Set values = new HashSet();
        values.add(AgentCompromiseAction.DONOTHING);
        AgentCompromiseAction action = new AgentCompromiseAction(agent, values, sb);
        _agentCache.put(agent, action);
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

