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
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.core.service.*;
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;
import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;

import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;

import edu.jhuapl.idmef.*;

import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;

/**
 * This class must be placed in the Node ini file to allow
 * Tomcat to report login failures. This essentially passes the NodeAgent's
 * service broker to Tomcat so that it can access the 
 * <code>BlackboardService</code> and <code>IdmefMessageFactory</code>
 * Services. Add the following line to your Node ini file's Plugins section:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.LoginFailureSensor
 * </pre>
 */
public class LoginFailureSensor extends ComponentPlugin {
  private DomainService _domainService = null;

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

  /**
   * Assigns the agent's service broker to the KeyRingJNDIRealm so that
   * login failures can be reported with the IDMEF service.
   */
  protected void setupSubscriptions() {
    SensorInfo          sensor       = new LFSensor();
    BlackboardService   bbs          = getBlackboardService();
    DomainService       ds           = getDomainService(); 
    CmrFactory          cmrFactory   = (CmrFactory) ds.getFactory("cmr");
    IdmefMessageFactory idmefFactory = cmrFactory.getIdmefMessageFactory();

    List capabilities = new ArrayList();
    capabilities.add(KeyRingJNDIRealm.LOGINFAILURE);
      
    RegistrationAlert reg = 
      idmefFactory.createRegistrationAlert( sensor, capabilities,
                                            idmefFactory.newregistration ,
                                            idmefFactory.SensorType);
    NewEvent regEvent = cmrFactory.newEvent(reg);
      
    boolean close = true;
    bbs.publishAdd(regEvent);
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
