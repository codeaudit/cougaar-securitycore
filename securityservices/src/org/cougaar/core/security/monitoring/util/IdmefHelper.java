/*
 * <copyright>
 *  Copyright 1997-2002 Networks Associates Technology, Inc.
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
package org.cougaar.core.security.monitoring.util;

// cougaar core classes
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;

// securityservices classes
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.plugin.UnknownSensorInfo;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;

import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.XMLUtils;

// java classes
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/* 
//for debugging purposes
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
*/

/**
 * Helper class to generate and publish IDMEF messages based on
 * FailureEvents.
 *
 * @see FailureEvents
 * @see MessageFailureSensor
 * @see AccessAgentProxy
 * @see MessageProtectionServiceImpl
 * @see CryptoManagerServiceImpl
 */
public class IdmefHelper {
  
  /**
   * Constructor
   *
   */
  public IdmefHelper(BlackboardService bbs, CmrFactory cmrFactory, 
    LoggingService logger, SensorInfo info) {
    m_blackboard = bbs;
    m_logger = logger;
    m_cmrFactory = cmrFactory;
    m_idmefFactory = m_cmrFactory.getIdmefMessageFactory();
    m_sensorInfo = info;
  }
  
  /**
   * method to publish an IDMEF message based on the events in the Collection.
   *
   * @param events a collection of events to publish as IDMEF messages
   */
  public void publishIDMEFAlerts(List events) {
    if(m_logger != null && 
       (events == null || 
        events.size() > 0)){
      m_logger.warn("event list is empty!");
      return; 
    }
   
    if(m_blackboard != null) {
      boolean debug = m_logger.isDebugEnabled();
      Iterator i = events.iterator();
      while(i.hasNext()) {
        FailureEvent evt = (FailureEvent)i.next();
        if(debug) {
          m_logger.debug("publishing message failure:\n" + evt);
        }
        Event e = createIDMEFAlert(evt);
        m_blackboard.openTransaction();
        m_blackboard.publishAdd(e);
        m_blackboard.closeTransaction();
      }
    }
  }
  
  /**
   * method to publish an IDMEF message based on the event
   *
   * @param event a failure event
   */
  public void publishIDMEFAlert(FailureEvent event) {
    if(m_logger != null &&
       event == null){
      m_logger.warn("no event to publish!");
      return; 
    }
    if(m_blackboard != null) {
      if(m_logger.isDebugEnabled()) {
          m_logger.debug("publishing message failure:\n" + event);
      }
      m_blackboard.openTransaction();
      m_blackboard.publishAdd(createIDMEFAlert(event));
      m_blackboard.closeTransaction();
    }
  }
  
  /**
   * private method to create an M&R domain objects
   */
  private Event createIDMEFAlert(FailureEvent event){
    List sources = new ArrayList(1);
    List targets = new ArrayList(1);
    List classifications = new ArrayList(1);
    List data = new ArrayList();
    List sRefList = new ArrayList(1);
    List tRefList = new ArrayList(1);
     
    String src = event.getSource();
    String tgt = event.getTarget();
    Address sAddr = m_idmefFactory.createAddress(src, null, Address.URL_ADDR);
    Address tAddr = m_idmefFactory.createAddress(tgt, null, Address.URL_ADDR);
    // the source and target are agents
    Source s = m_idmefFactory.createSource(null, null, null, null, null);
    Target t = m_idmefFactory.createTarget(null, null, null, null, null, null);
    // the 2 list specify agent reference the source and target object respectively
    sRefList.add(s.getIdent());
    tRefList.add(t.getIdent());
    // since there isn't a data model for cougaar Agents, the Agent object is
    // added to the AdditionalData of an IDMEF message
    Agent sAgent = m_idmefFactory.createAgent(src, null, null, sAddr, sRefList);
    Agent tAgent = m_idmefFactory.createAgent(tgt, null, null, tAddr, tRefList);
    sources.add(s);
    targets.add(t);
    // add the event classification to the classification list
		classifications.add(m_idmefFactory.createClassification(event.getClassification(), null));
		// add the agent information to the additional data
		data.add(m_idmefFactory.createAdditionalData(AdditionalData.STRING,
			                                           event.getReasonIdentifier(),
			                                           event.getReason()));
    data.add(m_idmefFactory.createAdditionalData(AdditionalData.STRING,
		                                             event.getDataIdentifier(),
			                                           event.getData()));
    data.add(m_idmefFactory.createAdditionalData("source-agent", sAgent));
    data.add(m_idmefFactory.createAdditionalData("target-agent", tAgent));
    // create the alert for this event
    Alert alert = m_idmefFactory.createAlert(m_sensorInfo, 
                                             event.getDetectTime(), 
                                             sources, 
                                             targets, 
                                             classifications,
                                             data);
    /*
    if(m_logger.isDebugEnabled()) {
      try {
        m_logger.debug("Alert in XML format:\n"); 
        DocumentBuilder m_docBuilder = 
          DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document document = m_docBuilder.newDocument();
        document.appendChild(alert.convertToXML(document));
        m_logger.debug(XMLUtils.doc2String(document));
      }
      catch( Exception e ){
        e.printStackTrace();
      }
    }
    */
    return m_cmrFactory.newEvent(alert);
  }
  
  // service needed to publish idmef messages
  private BlackboardService m_blackboard = null;
  // service needed to do some appropriate logging
  private LoggingService m_logger = null;
  // factory used to create events that are published to the blackboard
  private CmrFactory m_cmrFactory = null;
  // factory used to create idmef objects
  private IdmefMessageFactory m_idmefFactory = null;
  private SensorInfo m_sensorInfo = null;
}
