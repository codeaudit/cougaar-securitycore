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
import java.util.Iterator;
import java.util.Set;
import org.cougaar.coordinator.*;
import org.cougaar.coordinator.techspec.TechSpecNotFoundException;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.adaptivity.InterAgentOperatingMode;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.security.util.CommunityServiceUtilListener;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.Entity;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.thread.Schedulable;
import java.util.TimerTask;

public class ThreatConLevelSensor extends ComponentPlugin
{
    private LoggingService log;
    private ThreatConDiagnosis diagnosis;
    private ServiceBroker sb;
    private boolean techspecError = false;
    private String _communityName;
    private ThreadService threadService;

  private CommunityServiceUtil _csu;

    private IncrementalSubscription _subscription;
    private final UnaryPredicate INTER_AGENT_OPERATING_MODE =
      new UnaryPredicate() {
        public boolean execute(Object o) {
          if (o instanceof InterAgentOperatingMode) {
            return true;
          }    
          return false;
        }
      };

    private final UnaryPredicate diagnosisPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        return (o instanceof ThreatConDiagnosis);
      }
    };

    public void load() {
        super.load();
        sb = getServiceBroker();
        log = (LoggingService)sb.getService(this, LoggingService.class, null);

        threadService = (ThreadService) this.getServiceBroker().getService(this,
                ThreadService.class, null);
    }

    public synchronized void unload() {
        sb.releaseService(this, LoggingService.class, log);
        super.unload();
    }

  protected void setupSubscriptions() {
    _subscription = (IncrementalSubscription)
      blackboard.subscribe(INTER_AGENT_OPERATING_MODE);

    if (threadService != null) {
      servicesReady();
    }
    else {
      ServiceAvailableListener listener = new ServiceAvailableListener() {
        public void serviceAvailable(ServiceAvailableEvent ae) {
          Class sc = ae.getService();
          if (sc == ThreadService.class) {
            if (threadService != null) {
              return;
            }

            threadService = (ThreadService)
              getServiceBroker().getService(this,
                ThreadService.class, null);
            if (threadService != null) {
              servicesReady();
            }
          }
        }
      };
      getServiceBroker().addServiceListener(listener);
    }

    _csu = new CommunityServiceUtil(sb);
  }

    boolean start = true;
    public synchronized void execute() {

      if (start) {
        initThreatConDiagnosis();
      }

      // get the threatcon level change object, publish change
      if (_subscription.hasChanged()) {
      // notify all the agents in a particular enclave/security community 
        // leave to the old value, set or add will change it
          //removePolicies(_subscription.getRemovedCollection());
          //changeLevel(_subscription.getAddedCollection());
          changeLevel(_subscription.getChangedCollection());
      }


    }

    private void changeLevel(Collection c) {
      Iterator i = c.iterator();
      while(i.hasNext()) {
        InterAgentOperatingMode iaom = (InterAgentOperatingMode)i.next();
        // value - Comparable
        // set value
        try {
          String value = ThreatConActionInfo.NONEDiagnosis;
          if (iaom.getValue().equals("LOW")) {
            value = ThreatConActionInfo.LOWDiagnosis;
          }
          else if (iaom.getValue().equals("HIGH")) {
            value = ThreatConActionInfo.HIGHDiagnosis;
          }
          else {
            throw new IllegalValueException("InterAgentOperatingMode");
          }

          diagnosis.setValue(value);
          blackboard.publishChange(diagnosis);
          if (log.isDebugEnabled()) {
            log.debug(diagnosis + " changed.");
            log.debug(diagnosis.dump());
          }
        } catch (IllegalValueException e) { 
          log.error("Illegal value = "+iaom.getValue(), e);
        }
      }
        
    }

    private void initThreatConDiagnosis() {
      final CommunityServiceUtilListener csu = new CommunityServiceUtilListener() {
        public void getResponse(Set resp) {
          if (diagnosis != null) {
            return;
          }

          if(log.isDebugEnabled()){
            log.debug(" call back for community is called :" + resp );
          }

          if((resp!=null)&& (!resp.isEmpty())){
            Iterator it = resp.iterator();
            if (resp.size() > 1) {
              log.warn("there is only one community allowed!");
            }
            Community community = (Community)it.next();
            _communityName = community.getName();
            servicesReady(); 
          }

        }
      };
      _csu.getManagedSecurityCommunity(csu);
    }

  private synchronized void servicesReady() {
    if (_communityName != null && start && diagnosis == null) {
    try {
      throw new Throwable();
    } catch (Throwable t) {
      log.debug("diagnosis: " + diagnosis + " trace: ", t);
    }

        start = false;
      Schedulable sch = threadService.getThread(this, new CreateDiagnosisThread());
      sch.schedule(1);
      sch.start();
    }
  }

  class CreateDiagnosisThread extends TimerTask {
    public void run() {
      createDiagnosis(_communityName);
    }    

    private void createDiagnosis(String communityName) {
      if (techspecError) {
        return;
      }

      blackboard.openTransaction();
      Collection c = blackboard.query(diagnosisPredicate);
      Iterator iter = c.iterator();
      while (iter.hasNext()) {
        ThreatConDiagnosis thediagnosis = (ThreatConDiagnosis)iter.next();
        blackboard.publishRemove(thediagnosis);
      }
    
      if (log.isDebugEnabled()) {
        log.debug("initializing diagnosis for " + communityName);
      }

      try {
        diagnosis = new ThreatConDiagnosis(communityName, ThreatConActionInfo.NONEDiagnosis, sb);
        blackboard.publishAdd(diagnosis);
        if (log.isDebugEnabled()) {
          log.debug(diagnosis + " added.");
        }
      }
      catch (TechSpecNotFoundException e) {
                    log.error("TechSpec not found for ThreatConDiagnosis.  ");
         techspecError = true;
      }
      catch (IllegalValueException iv) {
        log.error("Failed to create diagnosis: " + iv);
      }
      blackboard.closeTransaction();
    }
  }
}

