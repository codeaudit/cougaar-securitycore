/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
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
package org.cougaar.core.security.monitoring.plugin;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;

import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.community.CommunityService;

import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Collection;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.NamingException;

import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;

import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.IDMEF_Process;

/**
 * This class must be placed in the Node ini file to allow
 * Tomcat to report login failures. This class reports the sensor
 * capabilities to the enclave security manager.
 * Add the following line to your Node ini file's Plugins section:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.LoginFailureSensor
 * </pre>
 * The plugin also takes an optional parameter indicating the role
 * of the security manager to report to. The default is "SecurityMnRManager".
 * The communities that the capabilities are sent to are all the ones that
 * this sensor belongs to.
 */
public class LoginFailureSensor extends ComponentPlugin {
  private DomainService  _domainService;
  private LoggingService _log;
  private String         _managerRole   = "SecurityMnRManager-Enclave";

  public LoginFailureSensor() {
  }

  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService aDomainService) {
    _domainService = aDomainService;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return _domainService;
  }

  public synchronized boolean setLoggingService() {
    if (_log != null) {
      return true;
    }

    ServiceBroker sb = getServiceBroker();
    if (sb == null) {
      return false;
    }
    
    _log = (LoggingService) sb.
      getService(this, LoggingService.class, null);
    return (_log != null);
  }

  /**
   * Sets the role to report capabilities to.
   */
  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List argument to setParameter");
    }
    List l = (List) o;
    if (l.size() > 1) {
      if (setLoggingService()) {
        _log.warn("Unexpected number of parameters given. Expecting 1, got " + 
                  l.size());
      }
    }
    if (l.size() > 0) {
      _managerRole = l.get(0).toString();
      if (setLoggingService() && _log.isInfoEnabled()) {
        _log.info("Setting Security Manager role to " + _managerRole);
      }
    }
  }

  /**
   * Assigns the agent's service broker to the KeyRingJNDIRealm so that
   * login failures can be reported with the IDMEF service.
   */
  protected void setupSubscriptions() {
    SensorInfo           sensor       = new LFSensor();
    BlackboardService    bbs          = getBlackboardService();
    DomainService        ds           = getDomainService(); 
    CmrFactory           cmrFactory   = (CmrFactory) ds.getFactory("cmr");
    IdmefMessageFactory  idmefFactory = cmrFactory.getIdmefMessageFactory();
    ServiceBroker        sb           = getBindingSite().getServiceBroker();
    AgentIdentificationService ais    = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null);
    String               agentName    = ais.getName();
    MessageAddress       myAddress    = ais.getMessageAddress();
    CommunityService     cs           = (CommunityService)
      sb.getService(this, CommunityService.class,null);

    setLoggingService();
    List capabilities = new ArrayList();
    capabilities.add(KeyRingJNDIRealm.LOGINFAILURE);
      
    RegistrationAlert reg = 
      idmefFactory.createRegistrationAlert( sensor, capabilities,
                                            idmefFactory.newregistration ,
                                            idmefFactory.SensorType);
    
    IDMEF_Node node = idmefFactory.getNodeInfo();
    IDMEF_Process process = idmefFactory.getProcessInfo();
    Source source = new Source(node, null, process, null, null, null, null);
    reg.setSources(new Source[] { source });
    
    NewEvent regEvent = cmrFactory.newEvent(reg);
    Collection communities = cs.listParentCommunities(agentName);
    Iterator iter = communities.iterator();
    boolean addedOne = false;
    while (iter.hasNext()) {
      String community = iter.next().toString();
      Attributes attrs = cs.getCommunityAttributes(community);
      boolean isSecurityCommunity = false;
      if (attrs != null) {
        Attribute  attr  = attrs.get("CommunityType");
        if (attr != null) {
          try {
            for (int i = 0; !isSecurityCommunity && i < attr.size(); i++) {
              if ("Security".equals(attr.get(i).toString())) {
                isSecurityCommunity = true;
              }
            }
          } catch (NamingException e) {
            // error reading value, so it can't be a Security community
          }
        }
      }
      if (isSecurityCommunity) {
        AttributeBasedAddress messageAddress = 
          new AttributeBasedAddress(community, "Role", _managerRole);
        CmrRelay relay = cmrFactory.newCmrRelay(regEvent, messageAddress);
        if (_log.isInfoEnabled()) {
          _log.info("Sending sensor capabilities to community '" + 
                    community + "'");
        }
        bbs.publishAdd(relay);
        addedOne = true;
      }
    }
    if (!addedOne) {
      _log.warn("This agent does not belong to any community. Login failures won't be reported.");
    }
    KeyRingJNDIRealm.initAlert(idmefFactory, cmrFactory, bbs, sensor);
  }  

  /**
   * dummy function doesn't do anything... no subscriptions are made.
   */
  protected void execute () {
  }

  private static class LFSensor implements SensorInfo {

    public String getName() {
      return "Login Failure Sensor";
    }

    public String getManufacturer() {
      return "NAI Labs";
    }

    public String getModel() {
      return "Servlet Login Failure";
    }
    
    public String getVersion() {
      return "1.0";
    }

    public String getAnalyzerClass() {
      return "org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm";
    }
  }
}
