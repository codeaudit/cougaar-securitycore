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
package org.cougaar.core.security.monitoring.plugin;

// cougaar core classes
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.multicast.AttributeBasedAddress;

// overlay class
import org.cougaar.core.security.constants.IdmefClassifications;

// securityservices classes
import org.cougaar.core.security.access.AccessAgentProxy;
import org.cougaar.core.security.crypto.CryptoManagerServiceImpl;
import org.cougaar.core.security.crypto.MessageProtectionServiceImpl;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.util.IdmefHelper;
import org.cougaar.core.security.monitoring.util.MessageFailureEvent;

// JavaIDMEF classes
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;

// java classes
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * This class must be placed in the Node ini file to allow
 * the AccessAgentProxy and EncryptionService to report message 
 * failures. This class reports the sensor capabilities to the 
 * enclave security manager.
 *
 * Add the following line to your Node ini file's Plugins section:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.MessageFailureSensor
 * </pre>
 * The plugin also takes an optional parameter indicating the role
 * of the security manager to report to. The default is "SecurityMnRManager-Enclave".
 * The communities that the capabilities are sent to are all the ones that
 * this sensor belongs to.
 */
public class MessageFailureSensor extends ComponentPlugin {
    
  public void setDomainService(DomainService aDomainService) {
    m_domainService = aDomainService;
    m_log = (LoggingService) getServiceBroker().
      getService(this, LoggingService.class, null);
  }
 
  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return m_domainService;
  }
  
  public void setParameter(Object o){
   if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List argument to setParameter");
    }
    List l = (List) o;
    if (l.size() > 1) {
      m_log.warn("Unexpected number of parameters given. Expecting 1, got " + 
                l.size());
    }
    if (l.size() > 0) {
      m_managerRole = l.get(0).toString();
      if (m_log.isInfoEnabled()) {
        m_log.info("Setting M&R Manager role to " + m_managerRole);
      }
    }
  }
  
  /**
   * Register this sensor's capabilities, and initialize the services that need to
   * to publish message failure events to this plugin's blackboard.
   * 
   */
  protected void setupSubscriptions() {
    SensorInfo sensorInfo = new MFSensorInfo();
    m_blackboard = getBlackboardService();
    ServiceBroker sb = getBindingSite().getServiceBroker();
    AgentIdentificationService ais    = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null);
    CommunityService cs = (CommunityService)
      sb.getService(this, CommunityService.class,null);
    m_cmrFactory = (CmrFactory) getDomainService().getFactory("cmr");
    m_idmefFactory = m_cmrFactory.getIdmefMessageFactory();
    LoggingService logger = m_log;
    if(logger == null) {
      logger = (LoggingService)sb.getService(this, LoggingService.class, null);
    }
    // register this sensor's capabilities
    registerCapabilities(cs, ais.getName());
    //initialize the IdmefHelper class in the following services
    IdmefHelper idmefHelper = 
      new IdmefHelper(m_blackboard, m_cmrFactory, logger, sensorInfo);
    AccessAgentProxy.initIdmefHelper(idmefHelper);
    CryptoManagerServiceImpl.initIdmefHelper(idmefHelper);
    MessageProtectionServiceImpl.initIdmefHelper(idmefHelper);
  }  
  
  /**
   * doesn't do anything
   */
  protected void execute(){
  }
  
  /**
   * register the capabilities of the sensor
   */
  private void registerCapabilities(CommunityService cs, String agentName){
    List capabilities = new ArrayList();
    Classification classification = 
      m_idmefFactory.createClassification(IdmefClassifications.MESSAGE_FAILURE, null);
    capabilities.add(classification);
      
    RegistrationAlert reg = 
      m_idmefFactory.createRegistrationAlert( this, capabilities,
                                              m_idmefFactory.newregistration ,
                                              m_idmefFactory.SensorType);
    NewEvent regEvent = m_cmrFactory.newEvent(reg);
    // get the list of communities that this agent belongs
    Collection communities = cs.listParentCommunities(agentName); 
    Iterator iter = communities.iterator();
    if (!iter.hasNext()) {
      m_log.warn("This agent does not belong to any community. Message Failure won't be reported.");
    }
    while(iter.hasNext()) {
      String community = iter.next().toString();
      // send the capability registeration to agents with in this community
      // that has the role specified by m_managerRole
      AttributeBasedAddress messageAddress = 
        new AttributeBasedAddress(community, "Role", m_managerRole);
      CmrRelay relay = m_cmrFactory.newCmrRelay(regEvent, messageAddress);
      if(m_log.isInfoEnabled()) {
        m_log.info("Sending sensor capabilities to community '" + 
                  community + "'" + ", role '" + m_managerRole + "'.");
      }
      m_blackboard.publishAdd(relay);
    }  
  }
  
  private class MFSensorInfo implements SensorInfo {
    /**
    * Get the name of the sensor/anaylzer.
    *
    * @return the name of the sensor
    */
    public String getName(){
      return "MessageFailureSensor";
    }
    /**
    * Get the sensor manufacturer.
    *
    * @return the sensor manufacturer
    */
    public String getManufacturer(){
      return "NAI Labs";
    }
   
    /**
    * Get the sensor model.
    *
    * @return the sensor model
    */
    public String getModel(){
      return "Cougaar Message Failure Sensor";
    }
  
    /**
    * Get the sensor version.
    *
    * @return the sensor version
    */
    public String getVersion(){
      return "1.0";
    }
   
    /**
    * Get the class of analyzer software and/or hardware.
    *
    * @return the sensor class
    */
    public String getAnalyzerClass(){
      return "Cougaar Security";
    } 
  }
  private BlackboardService m_blackboard;
  private DomainService m_domainService;
  private LoggingService m_log;
  private CmrFactory m_cmrFactory;
  private IdmefMessageFactory m_idmefFactory;
  private String m_managerRole = "SecurityMnRManager-Enclave"; // default value
}
