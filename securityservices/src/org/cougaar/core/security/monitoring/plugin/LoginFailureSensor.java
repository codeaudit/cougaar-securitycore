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
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.publisher.EventPublisher;
import org.cougaar.core.security.monitoring.publisher.LoginEventPublisher;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.services.auth.SecurityContextService;

import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.IDMEF_Process;
import edu.jhuapl.idmef.AdditionalData;

import org.cougaar.core.security.constants.IdmefClassifications;

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
public class LoginFailureSensor extends SensorPlugin {
 
  private String         _managerRole   = "Manager";

  private final  String[] CLASSIFICATIONS = {IdmefClassifications.LOGIN_FAILURE};
  private SensorInfo  sensor=null;
  public LoginFailureSensor() {
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
      throw new IllegalArgumentException("Unexpected number of parameters given. Expecting 1, got " + l.size());
    }
    if (l.size() > 0) {
      _managerRole = l.get(0).toString();
    }
  }



   protected SensorInfo getSensorInfo() {
    if(sensor == null) {
      sensor = new LFSensor();
    }
    return sensor;
  }

  protected  String []getClassifications() {
    return CLASSIFICATIONS;

  }

  protected  boolean agentIsTarget() {
    return true;
  }

  protected  boolean agentIsSource() {
    return false;

  }

  public static void publishEvent(FailureEvent event) {
    publishEvent(LoginFailureSensor.class, event);
  }

  /**
   * Assigns the agent's service broker to the KeyRingJNDIRealm so that
   * login failures can be reported with the IDMEF service.
   */
  protected void setupSubscriptions() {

    super.setupSubscriptions();

    if ( _log.isInfoEnabled()) {
      _log.info("Setting Security Manager role to " + _managerRole);
    }
    
    EventPublisher publisher =
      new LoginEventPublisher(_blackboard, _scs, _cmrFactory, _log, getSensorInfo());
    setPublisher(publisher);
    publishIDMEFEvent();
  }




  /**
   * Dummy function doesn't do anything. No subscriptions are made.
   */
  protected void execute () {
  }

  private static class LFSensor implements SensorInfo {

    public String getName() {
      return "Login Failure Sensor";
    }

    public String getManufacturer() {
      return "CSI";
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
