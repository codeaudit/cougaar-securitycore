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

// cougaar core classes
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.Entity;
import org.cougaar.core.service.MessageProtectionService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.util.UnaryPredicate;

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
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.security.util.CommunityServiceUtilListener;

// JavaIDMEF classes
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Alert;

// java classes
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.TimerTask;
import java.util.Set;

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
public abstract class SensorPlugin
  extends ComponentPlugin {

  private MessageAddress myAddress;
  
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
   * method to determine if the agent, the plugin is running in, is the target
   * of attacks
   */
  protected abstract boolean agentIsTarget();
   /**
   * method to determine if the agent, the plugin is running in, is the source
   * of attacks
   */
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
    myAddress = getAgentIdentifier();
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
    m_csu = new CommunityServiceUtil(sb);
    // register this sensor's capabilities
    getSecurityManager();
    /*
    Thread th=new Thread(new RegistrationTask());
    th.start();
    */
    //registerCapabilities(cs, m_agent);
  }  
  
  /**
   * doesn't do anything
   */
  protected void execute(){
  }
  
  private void getSecurityManager() {
    CommunityServiceUtilListener listener = new CommunityServiceUtilListener() {
	public void getResponse(Set entities) {
	  Iterator it = entities.iterator();
	  if (entities.size() == 0) {
	    m_log.warn("Could not find a security manager");
	  }
	  else if (entities.size() > 1) {
	    m_log.warn("Found more than one security manager");
	  }
	  else {
	    Entity entity = (Entity) it.next();
	    MessageAddress addr = MessageAddress.
	      getMessageAddress(entity.getName());
	    // Now register capabilities
	    registerCapabilities(addr);
	  }
	}
      };
    m_csu.findSecurityManager(myAddress.toString(), listener);
  }

  /**
   * register the capabilities of the sensor
   */
  private void registerCapabilities(MessageAddress myManager){
    List capabilities = new ArrayList();
    List targets = null;
    List sources=null;
    List data = null;
   
    if(myManager == null) {
      // manager may not have been initialize yet
      return; 
    }
    // if agent is the target then add the necessary information to the registration
    if(agentIsTarget()) {
      List tRefList = new ArrayList(1);
      targets = new ArrayList(1);
      data = new ArrayList(1);
      Address tAddr = m_idmefFactory.createAddress(myManager.toString(),
						   null, Address.URL_ADDR);
      Target t = m_idmefFactory.createTarget(null, null, null, null, null, null);
      // add the target ident to the reference ident list
      tRefList.add(t.getIdent());
      targets.add(t);
      // since there isn't a data model for cougaar Agents, the Agent object is
      // added to the AdditionalData of an IDMEF message
      Agent tAgent = m_idmefFactory.createAgent(myManager.toString(),
						null, null, tAddr, tRefList);
      data.add(m_idmefFactory.createAdditionalData(Agent.TARGET_MEANING, tAgent));
    }
    if(agentIsSource()) {
      List tRefList = new ArrayList(1);
      sources = new ArrayList(1);
      if(data==null) {
        data = new ArrayList(1);
      }
      Address tAddr = m_idmefFactory.createAddress(myManager.toString(),
						   null, Address.URL_ADDR);
      Source s = m_idmefFactory.createSource(null, null, null, null, null);
      // add the target ident to the reference ident list
      tRefList.add(s.getIdent());
      sources.add(s);
      // since there isn't a data model for cougaar Agents, the Agent object is
      // added to the AdditionalData of an IDMEF message
      Agent tAgent = m_idmefFactory.createAgent(myManager.toString(),
						null, null, tAddr, tRefList);
      data.add(m_idmefFactory.createAdditionalData(Agent.TARGET_MEANING, tAgent));
    }
    
    String []classifications = getClassifications();
    for(int i = 0; i < classifications.length; i++) {
      Classification classification = 
        m_idmefFactory.createClassification(classifications[i], null);
      capabilities.add(classification);
    }  

    m_blackboard.openTransaction();
    Collection c = 
      m_blackboard.query(new RegistrationPredicate(getSensorInfo(), 
                                                   targets, capabilities,
                                                   data, myManager.toString()));
    m_blackboard.closeTransaction();
    if (!c.isEmpty()) {
      m_log.info("Rehydrating - no need to publish sensor capabilities");
      return; // this is rehydrated and we've already registered
    } // end of if (!c.isEmpty())

    m_log.info("No rehydration - publishing sensor capabilities");
    RegistrationAlert reg = 
      m_idmefFactory.createRegistrationAlert( getSensorInfo(), 
                                              null,
                                              targets,
                                              capabilities,
                                              data,
                                              m_idmefFactory.newregistration,
                                              m_idmefFactory.SensorType,
                                              myManager.toString());
    NewEvent regEvent = m_cmrFactory.newEvent(reg);
    
    CmrRelay regRelay = m_cmrFactory.newCmrRelay(regEvent, myManager);
    m_blackboard.openTransaction();
    m_blackboard.publishAdd(regRelay);
    m_blackboard.closeTransaction();
    m_log.debug("Registered sensor successfully!");
    ServiceBroker sb =getBindingSite().getServiceBroker();
    if(sb!=null) {
      sb.releaseService(this,CommunityService.class,m_cs);
      m_cs=null;
    }
    return;
  }

  private class Semaphore {
    private int _available;
    public Semaphore(int max_available) {
      _available = max_available;
    }
    public synchronized int add() {
      return _available++;
    }
    public synchronized int remove() {
      return _available--;
    }
  }

  private void printCommunityInfo(CommunityService cs, Collection communities) {
    Iterator c = communities.iterator();
    final StringBuffer sb = new StringBuffer();
    final Semaphore communityNumber = new Semaphore(communities.size());

    while(c.hasNext()) {
      final String communityName = (String)c.next();
      CommunityResponseListener crl = new CommunityResponseListener() {
	  public void getResponse(CommunityResponse resp) {
	    Object response = resp.getContent();
	    if (!(response instanceof Set)) {
	      String errorString = "Unexpected community response class:"
		+ response.getClass().getName() + " - Should be a Set";
		m_log.error(errorString);
	      throw new RuntimeException(errorString);
	    }
	    Iterator it = ((Set)response).iterator();
	    while (it.hasNext()) {
	      Entity entity = (Entity) it.next();
	      sb.append("Manager for ").append(communityName).
		append(":").append(entity.getName()).append("\n");
	    }
	    int available = communityNumber.remove();
	    if (available == 0) {
	      // We have all the answers
	      m_log.debug(sb.toString());
	    }
	  }
	};
      cs.searchCommunity(communityName,
			 "(Role=" + m_managerRole + ")",
			 false, // not a recursive search
			 Community.AGENTS_ONLY,
			 crl);
    }
  }

  /**
   * method used to determine if the plugin is located in the same
   * agent as the enclave security manager
   * @deprecated
   */
  private boolean isSecurityManagerLocal(CommunityService cs,
					 String community,
					 String agentName) {

    Collection agents = null;
    // TODO: This method is not used anymore, but it would have to
    // be fixed if used again.
    //Collection agents = cs.searchByRole(community, m_managerRole);
    Iterator i = agents.iterator();
    
    while(i.hasNext()) {
      MessageAddress addr = (MessageAddress)i.next();
      if(addr.toString().equals(agentName)) {
        return true;
      }
    }
    return false;
  }

  /*
  class RegistrationTask extends TimerTask {
    int RETRY_TIME = 10 * 1000;
    int retryTime = RETRY_TIME;
    int counter = 1;

    public void run() {
      boolean  tryAgain = true;
      try {
        Thread.sleep(18 * retryTime);
      }
      catch(InterruptedException ix) {
        m_log.error("Was interrupted while delaying the polling of NS sleeping: " + ix);
        tryAgain = false;
      }
      
      while(tryAgain) {
        m_log.debug("Trying to register counter: " + counter++);
        tryAgain = registerCapabilities( m_agent);
        try {
          if(tryAgain) {
            if(counter < 6) { 
              retryTime=counter* RETRY_TIME;
            }
            Thread.sleep(retryTime);
          }
        }
        catch(InterruptedException ix) {
          m_log.error("Was interrupted while sleeping: " + ix);
          tryAgain = false;
        }
      } // while(tryAgain)
      // no longer need the community service util
      m_csu.releaseServices();
    } // public void run()
  } // class RegistrationTask
  
  */

  private static class RegistrationPredicate implements UnaryPredicate {
    private String _agent;
    private List _targets;
    private List _capabilities;
    private List _data;
    private String _agentName;
    private SensorInfo _sensor;

    public RegistrationPredicate(SensorInfo sensor,
                                 List targets,
                                 List capabilities,
                                 List data,
                                 String agentName) {
      _sensor = sensor;
      _targets = targets;
      _capabilities = capabilities;
      _data = data;
      _agent = agentName;
    }

    public static boolean arrayEquals(Object arr[], List list) {
      if ((arr == null || arr.length == 0) &&
          (list == null || list.size() == 0)) {
        return true;
      }
      if (arr == null || list == null || arr.length != list.size()) {
        return false;
      }

      Iterator iter = list.iterator();
      for (int i = 0; i < arr.length; i++) {
        Object o = iter.next();
        if (!(arr[i] == null && o == null)) {
          if (arr[i] == null || o == null) {
            return false;
          }
          if (!arr[i].equals(o)) {
            return false;
          }
        }
      }
      return true;
    }

    public boolean execute(Object o) {
      if (!(o instanceof CmrRelay)) {
        return false;
      } // end of if (!(o instanceof CmrRelay))
      CmrRelay cmr = (CmrRelay) o;
      Object content = cmr.getContent();
      if (!(content instanceof NewEvent)) {
        return false; // not a registration event
      } // end of if (!(content instanceof Event))
      NewEvent ev = (NewEvent) content;
      IDMEF_Message msg = ev.getEvent();
      if (!(msg instanceof RegistrationAlert)) {
        return false;
      } // end of if (!(msg instanceof RegistrationAlert))
      RegistrationAlert r = (RegistrationAlert) msg;
      if (!_agent.equals(r.getAgentName()) ||
          r.getOperation_type() != IdmefMessageFactory.newregistration ||
          !IdmefMessageFactory.SensorType.equals(r.getType())) {
        return false;
      }

      return (arrayEquals(r.getClassifications(),_capabilities) &&
              arrayEquals(r.getAdditionalData(),_data) &&
              arrayEquals(r.getTargets(),_targets) &&
              ((r.getAnalyzer() == null && _sensor.getModel() == null) ||
               (r.getAnalyzer() != null && 
                r.getAnalyzer().equals(_sensor.getModel()))));
    }
  }
  private CommunityServiceUtil m_csu;

  protected CommunityService m_cs;
  protected BlackboardService m_blackboard;
  protected DomainService m_domainService;
  protected LoggingService m_log;
  protected CmrFactory m_cmrFactory;
  protected IdmefMessageFactory m_idmefFactory;
  protected String m_agent;
  protected String m_managerRole = "Manager"; // default value
}
