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


package org.cougaar.core.security.certauthority;


import java.util.ArrayList;
import java.util.Enumeration;
import java.util.TimerTask;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.plugin.CompromiseBlackboard;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.CertificateManagementServiceClient;
import org.cougaar.core.security.util.SharedDataRelay;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.util.UnaryPredicate;


/**
 * Revoke and agents certificate. Subscribes to relay
 *
 * @author ttschampel
 */
public class RevokeAgentCertificatePlugin extends ComponentPlugin {
  /** Plugin name */
  private static final String pluginName = "RevokeAgentCerficatePlugin";
  /** Subscription to relay */
  private IncrementalSubscription relaySubs = null;
  /** Predicate for relay */
  private UnaryPredicate relayPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof SharedDataRelay) {
        SharedDataRelay sdr = (SharedDataRelay) o;
        if ((sdr.getContent() != null) && sdr.getContent() instanceof Task) {
          Task t = (Task) sdr.getContent();
          return (t.getVerb() != null) && t.getVerb().toString().equals(CompromiseBlackboard.REVOKE_AGENT_CERT_VERB);
        }
      }

      return false;
    }
  };

  /** Logging Service */
  private LoggingService logging = null;

  /**
   * Set Logging Service
   *
   * @param s LoggingService
   */
  public void setLoggingService(LoggingService s) {
    this.logging = s;
  }


  /**
   * Setup subscriptions
   */
  protected void setupSubscriptions() {
    this.relaySubs = (IncrementalSubscription) getBlackboardService().subscribe(this.relayPredicate);

  }


  /**
   * Process subscriptions
   */
  protected void execute() {
    if (logging.isDebugEnabled()) {
      logging.debug(pluginName + " executing");
    }

    checkForNewTasks();
  }


  /**
   * Check if there are new revoke agent tasks
   */
  private void checkForNewTasks() {
    Enumeration enumeration = this.relaySubs.getAddedList();
    while (enumeration.hasMoreElements()) {
      SharedDataRelay sdr = (SharedDataRelay) enumeration.nextElement();
      Task task = (Task) sdr.getContent();
      if (logging.isDebugEnabled()) {
        logging.debug("Got mesage to revoke agent:" + task);
      }

      //get caDNs
      ArrayList caDNs = (ArrayList) task.getPrepositionalPhrase(CompromiseBlackboard.CA_DN_PREP).getIndirectObject();

      //get agent name
      String agentName = (String) task.getPrepositionalPhrase(CompromiseBlackboard.FOR_AGENT_PREP).getIndirectObject();
      if (caDNs == null) {
        if (logging.isErrorEnabled()) {
          logging.error("Recevied revoke agent request without a CADN");
        }
      } else {
        for (int i = 0; i < caDNs.size(); i++) {
          String caDN = (String) caDNs.get(i);
          if (logging.isDebugEnabled()) {
            logging.debug("Revoke agent cert for " + agentName + " and caDN:" + caDN);
          }

          try {
            CertificateManagementService keymanagement = (CertificateManagementService) this.getServiceBroker().getService(new CertificateManagementServiceClientImpl(caDN), CertificateManagementService.class, null);
            if (keymanagement == null) {
              if (logging.isDebugEnabled()) {
                logging.debug("CertificateManagementService  is null");
              }
            }
            
            //keymanagement.revokeAgentCertificate(caDN, agentName);
            RevokeTask revokeTask = new RevokeTask(caDN, agentName, keymanagement);
            ThreadService threadService = (ThreadService)this.getServiceBroker().getService(this, ThreadService.class, null);
            Schedulable sch = threadService.getThread(this, revokeTask);
            sch.schedule(1);
            sch.start();
         
          } catch (Exception e) {
            if (logging.isErrorEnabled()) {
              logging.error("Error has occured due to  following reason", e);
            }
          }
        }
      }

      sdr.updateResponse(sdr.getSource(), task);
      getBlackboardService().publishChange(sdr);
    }
  }

  private class CertificateManagementServiceClientImpl implements CertificateManagementServiceClient {
    private String caDN;

    public CertificateManagementServiceClientImpl(String aCaDN) {
      caDN = aCaDN;
    }

    public String getCaDN() {
      return caDN;
    }
  }
  
  private class RevokeTask extends TimerTask{
  	String caDn = null;
  	String agentName = null;
  	CertificateManagementService keymanagement  = null;
  	 public RevokeTask(String caDn,  String agentName, CertificateManagementService keymanagement){
  	 	this.caDn = caDn;
  	 	this.agentName = agentName;	
  	 	this.keymanagement = keymanagement;
  	 }
  	  public void run(){
  	  			if(logging.isDebugEnabled()){
  	  				logging.debug("Revoking agent cert:" + agentName);
  	  			}
  	  			try{
					keymanagement.revokeAgentCertificate(caDn, agentName);
  	  			}catch(Exception e){
  	  				if(logging.isErrorEnabled()){
  	  					logging.error("Error revoking agent cert",e);
  	  				}
  	  			}
  	  	
  	  }
  }
}
