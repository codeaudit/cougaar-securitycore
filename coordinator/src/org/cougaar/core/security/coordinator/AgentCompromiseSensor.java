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

package org.cougaar.core.security.coordinator;

import java.util.Collection;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Hashtable;
import java.util.Set;
import java.util.Enumeration;
import org.cougaar.coordinator.*;
import org.cougaar.coordinator.techspec.TechSpecNotFoundException;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.security.coordinator.AgentCompromiseInfo;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.security.util.CommunityServiceUtilListener;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.Entity;

public class AgentCompromiseSensor extends ComponentPlugin
{
    private LoggingService log;
    private ServiceBroker sb;
    private boolean start = true; 
    private Hashtable _agentCache = new Hashtable();
  private CommunityServiceUtil _csu;
    private boolean techspecError = false;

    private IncrementalSubscription _subscription;
    private final UnaryPredicate coordinatorPredicate =
      new UnaryPredicate() {
        public boolean execute(Object o) {
          if (o instanceof AgentCompromiseInfo) {
            return ((AgentCompromiseInfo)o).getType().equals(AgentCompromiseInfo.SENSOR);
          }    
          return false;
        }
      };

    private final UnaryPredicate diagnosisPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        return (o instanceof AgentCompromiseDiagnosis);
      }
    };

    public void load() {
        super.load();
        sb = getServiceBroker();
        log = (LoggingService)sb.getService(this, LoggingService.class, null);

        _csu = new CommunityServiceUtil(sb);
                blackboard.signalClientActivity();
    }

    public synchronized void unload() {
        sb.releaseService(this, LoggingService.class, log);
        super.unload();
    }

  protected void setupSubscriptions() {
    _subscription = (IncrementalSubscription)
      blackboard.subscribe(coordinatorPredicate);

  }

    public synchronized void execute() {
      if (start) {
        initAgentCompromiseDiagnosis();
      }

      // get the threatcon level change object, publish change
      // notify all the agents in a particular enclave/security community 
      changeLevel(_subscription.getAddedCollection());


    }

    private void changeLevel(Collection c) {
      Iterator i = c.iterator();
      while(i.hasNext()) {
        AgentCompromiseInfo info = (AgentCompromiseInfo)i.next();

        AgentCompromiseDiagnosis diagnosis = (AgentCompromiseDiagnosis)_agentCache.get(info.getSourceAgent());
        if (diagnosis == null) {
          log.warn("Agent " + info.getSourceAgent() + " diagnosis not found in cache!");
          continue;
        }
 
        // value - Comparable
        // set value
        try {
          diagnosis.setValue(info.getDiagnosis());
          diagnosis.setCompromiseInfo(info);
          blackboard.publishChange(diagnosis);
          if (log.isDebugEnabled()) {
            log.debug(diagnosis + " changed.");
            log.debug(diagnosis.dump());
          }
        } catch (IllegalValueException e) { 
          log.error("Illegal value = "+info.getDiagnosis(), e);
        }

//        blackboard.publishRemove(info);

      }
        
    }

    private void initAgentCompromiseDiagnosis() {
      Collection c = blackboard.query(diagnosisPredicate);
      Iterator iter = c.iterator();
      while (iter.hasNext()) {
        AgentCompromiseDiagnosis diagnosis = (AgentCompromiseDiagnosis)iter.next();
        blackboard.publishRemove(diagnosis);
      }

      final CommunityServiceUtilListener csu = new CommunityServiceUtilListener() {
        public void getResponse(Set agents) {
          setupRole(agents);
        }
      };
      _csu.getCommunityAgent(CommunityServiceUtil.MONITORING_SECURITY_COMMUNITY_TYPE, 
        CommunityServiceUtil.MEMBER_ROLE, csu, true);
    }

    private synchronized void setupRole(Set agents) {
          if(log.isDebugEnabled()){
            log.debug(" call back for community is called :" + agents );
          }
          Iterator it = agents.iterator();
          blackboard.openTransaction();
          while (it.hasNext()) {
            Entity agent = (Entity)it.next();  
            String agentName = agent.getName();
            // new entity?
            if (_agentCache.get(agentName) == null) {
              createDiagnosis(agentName);
            }
          }

          blackboard.closeTransaction();
    }

    private void createDiagnosis(String agent) {
      if (techspecError) {
        return;
      }

      if (log.isDebugEnabled()) {
        log.debug("initializing diagnosis for " + agent);
      }

        start = false;
      try {
        AgentCompromiseDiagnosis diagnosis = new AgentCompromiseDiagnosis(agent, sb);
        _agentCache.put(agent, diagnosis);
        blackboard.publishAdd(diagnosis);
        if (log.isDebugEnabled()) {
          log.debug(diagnosis + " added.");
        }
      }
      catch (TechSpecNotFoundException e) {
                    log.warn("TechSpec not found for AgentCompromiseDiagnosis. ");
        techspecError = true;
      }
    }
}

