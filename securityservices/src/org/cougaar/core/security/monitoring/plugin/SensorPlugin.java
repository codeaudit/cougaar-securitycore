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
import org.cougaar.core.service.MessageProtectionService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.core.mts.MessageAddress;

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
import org.cougaar.core.security.services.crypto.EncryptionService;

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
import java.util.TimerTask;

/**
 * abstract sensor class that registers the capabilities of the sensor
 * two methods must be implemented in the subclass:
 *
 * getSensorInfo
 * getClassifications
 * agentIsTarget
 *
 * subclass setupSubscription must call super.setupSubscription inorder
 * for the registration to take place.
 */
public abstract class SensorPlugin extends ComponentPlugin {
  
  /**
   * method to obtain the sensor info for the concrete class
   */  
  protected abstract SensorInfo getSensorInfo();
  /**
   * method to obtain the list of classification the sensor is capable of
   * detecting
   */ 
  protected abstract String []getClassifications();
  /**
   * method to determine if the agent the plugin is running is the target
   * of attacks
   */
  protected abstract boolean agentIsTarget();
  
  protected abstract boolean agentIsSource();
  
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


   public void setCommunityService(CommunityService cs) {
    //System.out.println(" set community services Servlet component :");
     this.m_cs=cs;
   }
   public CommunityService getCommunityService() {
     return this.m_cs;
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
      if (m_log != null && m_log.isInfoEnabled()) {
        m_log.info("Setting M&R Manager role to " + m_managerRole);
      }
    }
  }
  
  /**
   * Register this sensor's capabilities
   */
  protected void setupSubscriptions() {
    
    m_blackboard = getBlackboardService();
    ServiceBroker sb = getBindingSite().getServiceBroker();
    AgentIdentificationService ais    = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null);
    m_agent = ais.getName();
    m_cmrFactory = (CmrFactory) getDomainService().getFactory("cmr");
    m_idmefFactory = m_cmrFactory.getIdmefMessageFactory();
    if(m_log == null) {
      m_log = (LoggingService)sb.getService(this, LoggingService.class, null);
    }
    // register this sensor's capabilities
      Thread th=new Thread(new RegistrationTask());
      th.start();
     //registerCapabilities(cs, m_agent);
    }  
  
    /**
    * doesn't do anything
    */
    protected void execute(){
    }
  
   /**
    * register the capabilities of the sensor
    */
    private boolean registerCapabilities( String agentName){
      List capabilities = new ArrayList();
      List targets = null;
      List sources=null;
      List data = null;
   
      if(m_cs == null) {
        return true;
      }
      Collection manager = getEnclaveManager();
      if(manager == null) {
  	return false;
      }
      else if(manager.size() == 0) {
 	m_log.warn("Enclave Security Manager not yet alive!");
  	return true; // enclave managers not yet alive
      }  
      // if agent is the target then add the necessary information to the registration
      if(agentIsTarget()) {
        List tRefList = new ArrayList(1);
	targets = new ArrayList(1);
	data = new ArrayList(1);
        Address tAddr = m_idmefFactory.createAddress(agentName, null, Address.URL_ADDR);
        Target t = m_idmefFactory.createTarget(null, null, null, null, null, null);
       // add the target ident to the reference ident list
        tRefList.add(t.getIdent());
        targets.add(t);
        // since there isn't a data model for cougaar Agents, the Agent object is
        // added to the AdditionalData of an IDMEF message
        Agent tAgent = m_idmefFactory.createAgent(agentName, null, null, tAddr, tRefList);
        data.add(m_idmefFactory.createAdditionalData(Agent.TARGET_MEANING, tAgent));
      }
      if(agentIsSource()) {
	List tRefList = new ArrayList(1);
        sources = new ArrayList(1);
	if(data==null) {
	  data = new ArrayList(1);
	}
	Address tAddr = m_idmefFactory.createAddress(agentName, null, Address.URL_ADDR);
	Source s = m_idmefFactory.createSource(null, null, null, null, null);
	// add the target ident to the reference ident list
	tRefList.add(s.getIdent());
	sources.add(s);
	// since there isn't a data model for cougaar Agents, the Agent object is
	// added to the AdditionalData of an IDMEF message
	Agent tAgent = m_idmefFactory.createAgent(agentName, null, null, tAddr, tRefList);
	data.add(m_idmefFactory.createAdditionalData(Agent.TARGET_MEANING, tAgent));
      }
    
      String []classifications = getClassifications();
      for(int i = 0; i < classifications.length; i++) {
	Classification classification = 
	  m_idmefFactory.createClassification(classifications[i], null);
	capabilities.add(classification);
      }  
      RegistrationAlert reg = 
	m_idmefFactory.createRegistrationAlert( getSensorInfo(), 
                                              null,
                                              targets,
                                              capabilities,
                                              data,
                                              m_idmefFactory.newregistration,
                                              m_idmefFactory.SensorType,
                                              agentName);
    NewEvent regEvent = m_cmrFactory.newEvent(reg);
    
    CmrRelay regRelay = m_cmrFactory.newCmrRelay(regEvent, (MessageAddress)manager.iterator().next());
    m_blackboard.openTransaction();
    m_blackboard.publishAdd(regRelay);
    m_blackboard.closeTransaction();
    m_log.debug("Registered sensor successfully!");
    ServiceBroker sb =getBindingSite().getServiceBroker();
    if(sb!=null) {
      sb.releaseService(this,CommunityService.class,m_cs);
      m_cs=null;
    }
    return false;
  }

    
  private void printCommunityInfo(CommunityService cs, Collection communities) {
    Iterator c = communities.iterator();
    while(c.hasNext()) {
      String community = (String)c.next();
      m_log.debug("### community = " + community);
      Collection agents = cs.searchByRole(community, m_managerRole);
      Iterator i = agents.iterator();
      while(i.hasNext()) {
        m_log.debug("##### SearchByRole: " + i.next()); 
      }
    }
  }

   private Collection getEnclaveManager() {
      Collection community = m_cs.listParentCommunities(m_agent, "(CommunityType=Security)");
      if(community.size() > 1) {
	  m_log.error(m_agent + " should belong to only one Security community!");
	  return null;
      }
      else if(community.size() == 0) {
	  m_log.warn("Security Manager may not have registered yet!");
	  return community;
      }
      printCommunityInfo(m_cs, community);
      
      String communityName = community.iterator().next().toString();
      Collection managers = m_cs.searchByRole(communityName, m_managerRole);          
      if(managers.size() > 1) {
	  m_log.error("There are " + managers.size() + " Enclave Security Manager in community=" + communityName);
	return null;
      }
      return managers;
   }  
  /**
   * method used to determine if the plugin is located in the same
   * agent as the enclave security manager
   */
  private boolean isSecurityManagerLocal(CommunityService cs, String community, String agentName) {
    Collection agents = cs.searchByRole(community, m_managerRole);
    Iterator i = agents.iterator();
    
    while(i.hasNext()) {
      MessageAddress addr = (MessageAddress)i.next();
      if(addr.toString().equals(agentName)) {
        return true;
      }
    }
    return false;
  }

  class RegistrationTask extends TimerTask {
    int RETRY_TIME = 10 * 1000;
    int retryTime = RETRY_TIME;
    int counter = 1;
    public void run() {
	boolean  tryAgain = true;
	try {
	  Thread.sleep(18*retryTime);
	}
	catch(InterruptedException ix) {
	  m_log.error("Was interrupted while delaying the polling of NS sleeping: " + ix);
	  tryAgain = false;
	}
	//boolean neverfalse=true;
	while(tryAgain) {
	    m_log.debug("Trying to register counter: " + counter++);
	    tryAgain = registerCapabilities( m_agent);
	    try {
		if(tryAgain) {
		  if(counter<6) { 
		    retryTime=counter* RETRY_TIME;
		  }
		    Thread.sleep(retryTime);
		}
	     }
            catch(InterruptedException ix) {
		m_log.error("Was interrupted while sleeping: " + ix);
		tryAgain = false;
            }
	}
    }
  }
  
 
  protected CommunityService m_cs;
  protected BlackboardService m_blackboard;
  protected DomainService m_domainService;
  protected LoggingService m_log;
  protected CmrFactory m_cmrFactory;
  protected IdmefMessageFactory m_idmefFactory;
  protected String m_agent;
  protected String m_managerRole = "SecurityMnRManager-Enclave"; // default value
  
}
