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


package org.cougaar.core.security.monitoring.plugin;


import java.io.Serializable;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.DetectTime;


/**
 * Monitors the Blackboard for Blackboard Compromise.  Then publishes an IDMEF
 * Event  reporting the compromise along with the time of the compromise
 *
 * @author ttschampel
 */
public class BlackboardCompromiseSensorPlugin extends ComponentPlugin {
  
  /** Plugin name */
  private String pluginName = "BlackboardCompromisePlugin";
  /** Subscription to Compromise Blackboard Objects */
  private IncrementalSubscription compromiseSubs = null;
  /** LoggingService */
  private LoggingService logging = null;
  /** Predicate for CompromiseBlackboard Objects */
  private UnaryPredicate compromisePredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      return o instanceof CompromiseBlackboard;
    }
  };

  /**
   * Set Logging Service
   *
   * @param service LoggingService
   */
  public void setLoggingService(LoggingService service) {
    this.logging = service;


  }


  /**
   * setup subscriptions
   */
  public void setupSubscriptions() {
    compromiseSubs = (IncrementalSubscription) this.getBlackboardService().subscribe(compromisePredicate);
  }


  /**
   * Check for Compromise Blackboard Objects
   */
  public void execute() {
    if (logging.isDebugEnabled()) {
      logging.debug(pluginName + " executing");
    }

    Enumeration enumeration = compromiseSubs.getAddedList();
    if (enumeration.hasMoreElements()) {
      CompromiseBlackboard cb = (CompromiseBlackboard) enumeration.nextElement();
      long timestamp = cb.getTimestamp();
      if (logging.isWarnEnabled()) {
        logging.warn("Blackboard has been compromised at time " + new Date(timestamp) + ", sending restart");
      }
	  String compromiseType = cb.getCompromiseType();
      //create IDMEF Event
      createIDMEFEvent(timestamp, pluginName, CompromiseBlackboard.CLASSIFICATION, compromiseType);
      getBlackboardService().publishRemove(cb);
    }
  }


  /**
   * Create IDMEF Event
   *
   * @param timestamp DOCUMENT ME!
   * @param sensorName DOCUMENT ME!
   * @param classification DOCUMENT ME!
   */
  protected void createIDMEFEvent(long timestamp, final String sensorName, String classification, String compromiseType) {
    DetectTime detectTime = new DetectTime();
    detectTime.setIdmefDate(new java.util.Date(timestamp));
    DomainService domainService = (DomainService) this.getServiceBroker().getService(this, DomainService.class, null);
    CmrFactory cmrFactory = (CmrFactory) domainService.getFactory("cmr");
    ArrayList classifications = new ArrayList();
    Classification c = (Classification) cmrFactory.getIdmefMessageFactory().createClassification(classification, null);
    classifications.add(c);
    Analyzer a = cmrFactory.getIdmefMessageFactory().createAnalyzer(new SensorInfo() {
        public String getName() {
          return sensorName;
        }


        public String getManufacturer() {
          return "CSI";
        }


        public String getModel() {
          return "BlackboardTool";
        }


        public String getVersion() {
          return "1.0";
        }


        public String getAnalyzerClass() {
          return pluginName;
        }
      });
      
  //For now just use agent, host, and node of this agent, but in the future the sensor could be getting notified of a compromise 
  //from a different agent.
  
	ArrayList sources = new ArrayList();
	sources.add(this.getAgentIdentifier().getAddress());
	
	ArrayList dataList = new ArrayList();
	//add scope of compromise
	AdditionalData data =new AdditionalData();
	data.setType("scope");
	data.setAdditionalData(compromiseType);
	dataList.add(data);
	//Add timestamp of compromise
	AdditionalData timeData = new AdditionalData();
	timeData.setType("compromise timestamp");
	timeData.setAdditionalData("" + timestamp);
	dataList.add(timeData);
	//Add source Agent
	AdditionalData agentData = new AdditionalData();
	agentData.setType("sourceAgent");
	agentData.setAdditionalData(this.getAgentIdentifier().getAddress());
	dataList.add(agentData);
	//Add source Node
	AdditionalData nodeData = new AdditionalData();
	nodeData.setType("sourceNode");
	NodeIdentificationService nodeIdService = (NodeIdentificationService)this.getServiceBroker().getService(this,NodeIdentificationService.class, null);
	String nodeName = nodeIdService.getMessageAddress().getAddress();
	nodeData.setAdditionalData(nodeName);
	dataList.add(nodeData);
	//Add source host
	AdditionalData hostData = new AdditionalData();
	hostData.setType("sourceHost");
	try{
	InetAddress inetAddress = InetAddress.getLocalHost();
	String hostName = inetAddress.getHostName();
	hostData.setAdditionalData(hostName);
	dataList.add(hostData);
	}catch(Exception e){
		if(logging.isErrorEnabled()){
			logging.error("Unable to get host information");
		}
	}
	
    Alert alert = cmrFactory.getIdmefMessageFactory().createAlert(a, detectTime, null, null, classifications, dataList);
    if (logging.isInfoEnabled()) {
      logging.info("*****************************Publishing IDMEF Event");
    }

    Event event = cmrFactory.newEvent(alert);
	
    if (!(event instanceof Serializable)) {
      if (logging.isErrorEnabled()) {
        logging.error("Event is not serializable");
      }
    }

    getBlackboardService().publishAdd(event);

  }
}