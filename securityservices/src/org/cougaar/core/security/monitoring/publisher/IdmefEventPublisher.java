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
package org.cougaar.core.security.monitoring.publisher;

// cougaar core classes
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;

// securityservices classes
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.plugin.UnknownSensorInfo;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.services.auth.SecurityContextService;

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
 * class to generate and publish IDMEF messages based on
 * FailureEvents.
 *
 * @see FailureEvents
 * @see MessageFailureSensor
 * @see DataProtectionSensor
 */
public class IdmefEventPublisher implements EventPublisher {

  /**
   * Constructor
   */
  public IdmefEventPublisher(BlackboardService bbs, 
                             SecurityContextService scs, 
                             CmrFactory cmrFactory, 
                             LoggingService logger, 
                             SensorInfo info,
                             ThreadService ts) {
    _blackboard = bbs;
    _scs = scs;
    _logger = logger;
    _cmrFactory = cmrFactory;
    _idmefFactory = _cmrFactory.getIdmefMessageFactory();
    _sensorInfo = info;
    // get the sensor's execution context
    _ec = _scs.getExecutionContext();
    _threadService = ts;
  }
  
  /**
   * method to publish an IDMEF message based on the events in the Collection.
   *
   * @param events a collection of events to publish as IDMEF messages
   */
  public void publishEvents(List events) {
    if((events == null ||
        events.size() == 0)){
      if(_logger != null) {
        _logger.warn("event list is empty!");
      }
      return;
    }
    Iterator i = events.iterator();
    while(i.hasNext()) {
      publishEvent((FailureEvent)i.next());
    }
  }

  /**
   * method to publish an IDMEF message based on the event
   *
   * @param event a failure event
   */
  public void publishEvent(final FailureEvent event) {
    //boolean openTransaction = false;
    if(event == null){
      if(_logger != null) {
        _logger.warn("no event to publish!");
      }
      return;
    }
		
    if(_blackboard != null) {
      if(_logger.isDebugEnabled()) {
        _logger.debug("publishing message failure:\n" + event);
      }
      //openTransaction= _blackboard.isTransactionOpen();
      //if(!openTransaction) {
      _scs.setExecutionContext(_ec);
      final boolean lock[] = new boolean[1];
      Runnable publishIt = new Runnable() {
          public void run() {
            _blackboard.openTransaction();
            _blackboard.publishAdd(createIDMEFAlert(event));
            _blackboard.closeTransaction();
            synchronized (lock) {
              lock[0] = true;
              lock.notifyAll();
            }
          }
        };
      Schedulable s = _threadService.getThread(this, publishIt);
      s.start();
      synchronized (lock) {
        while (lock[0] == false) {
          try {
            lock.wait();
          } catch (Exception e) {}
        }
      }
      _scs.resetExecutionContext();
    }
  }

  /**
   * private method to create an M&R domain objects
   */
  protected Event createIDMEFAlert(FailureEvent event){
    List sources = null;
    List targets = null;
    List classifications = new ArrayList(1);
    List data = new ArrayList();
    Source s = null;
    Target t = null;
    Agent sAgent = null;
    Agent tAgent = null;

    String src = event.getSource();
    String tgt = event.getTarget();

    // create source information for the IDMEF event
    if(src != null) {
      List sRefList = new ArrayList(1);
      Address sAddr = _idmefFactory.createAddress(src, null, Address.URL_ADDR);
      sources = new ArrayList(1);
      s = _idmefFactory.createSource(null, null, null, null, null);
      sRefList.add(s.getIdent());
      sAgent = _idmefFactory.createAgent(src, null, null, sAddr, sRefList);
      sources.add(s);
    }
    // create target information for the IDMEF event
    if(tgt != null) {
      List tRefList = new ArrayList(1);
      Address tAddr = _idmefFactory.createAddress(tgt, null, Address.URL_ADDR);
      targets = new ArrayList(1);
      t = _idmefFactory.createTarget(null, null, null, null, null, null);
      tRefList.add(t.getIdent());
      tAgent = _idmefFactory.createAgent(tgt, null, null, tAddr, tRefList);
      targets.add(t);
    }
    // add the event classification to the classification list
    classifications.add(_idmefFactory.createClassification(event.getClassification(), null));
    String reason = event.getReason();
    String evtData = event.getData();
    if(reason != null) {
      data.add(_idmefFactory.createAdditionalData(AdditionalData.STRING,
			                                             event.getReasonIdentifier(),
			                                             event.getReason()));
    }
    if(evtData != null) {
      data.add(_idmefFactory.createAdditionalData(AdditionalData.STRING,
		                                               event.getDataIdentifier(),
			                                             event.getData()));
    }
    // since there isn't a data model for cougaar Agents, the Agent object is
    // added to the AdditionalData of an IDMEF message
    if(sAgent != null) {
      data.add(_idmefFactory.createAdditionalData(Agent.SOURCE_MEANING, sAgent));
    }
    if(tAgent != null) {
      data.add(_idmefFactory.createAdditionalData(Agent.TARGET_MEANING, tAgent));
    }
    // check if any data has been added to the additional data
    if(data.size() == 0) {
      data = null;
    }
    // create the alert for this event
    Alert alert = _idmefFactory.createAlert(_sensorInfo,
                                             event.getDetectTime(),
                                             sources,
                                             targets,
                                             classifications,
                                             data);
    /*
    if(_logger.isDebugEnabled()) {
      try {
        _logger.debug("Alert in XML format:\n");
        DocumentBuilder _docBuilder =
          DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document document = _docBuilder.newDocument();
        document.appendChild(alert.convertToXML(document));
        _logger.debug(XMLUtils.doc2String(document));
      }
      catch( Exception e ){
        e.printStackTrace();
      }
    }
    */
    return _cmrFactory.newEvent(alert);
  }

  // service needed to publish idmef messages
  protected BlackboardService _blackboard = null;
  // service used to track the security context
  protected SecurityContextService _scs = null;
  // service needed to do some appropriate logging
  protected LoggingService _logger = null;
  // factory used to create events that are published to the blackboard
  protected CmrFactory _cmrFactory = null;
  // factory used to create idmef objects
  protected IdmefMessageFactory _idmefFactory = null;
  protected SensorInfo _sensorInfo = null;
  protected ThreadService _threadService = null;
  private final ExecutionContext _ec;
}
 
