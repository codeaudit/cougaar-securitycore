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

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.core.service.*;
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;

import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;

import edu.jhuapl.idmef.*;


public class TestDummySensorPlugin  extends  ComponentPlugin   {
  private LoggingService log;
  private DomainService domainService = null;
  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService aDomainService) {
    domainService = aDomainService;
  }


  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
  }

    
  protected void setupSubscriptions() {
    log = (LoggingService)
      getBindingSite().getServiceBroker().getService(this,
			       LoggingService.class, null);

    log.debug("setupSubscriptions of Test dummy sensor called :"); 
    DomainService service=getDomainService();
    if(service==null) {
      log.debug(" Got service as null in Test Dummy Sensor  :");
      return;
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    TestDummySensor sensor=new TestDummySensor("sensor1");
     List capabilities = new ArrayList();
    capabilities.add( imessage.createClassification( "POD", null  ) );
    capabilities.add( imessage.createClassification( "TCPSCAN", null  ) );
    capabilities.add( imessage.createClassification( "LOGINFAILURE", null  ) );
    
    RegistrationAlert reg=imessage.createRegistrationAlert(sensor,capabilities,IdmefMessageFactory.newregistration);
    
    NewEvent event=factory.newEvent(reg);
    log.debug(" going to publish capabilities in Test Dummy sensor :");
    getBlackboardService().publishAdd(event);
    getBlackboardService().closeTransaction();
    sensor=new TestDummySensor("sensor2");
    capabilities.add( imessage.createClassification( "SecurityManager", null  ) ); 
    capabilities.add( imessage.createClassification( "JarVerification", null  ) );
     
    reg=imessage.createRegistrationAlert(sensor,capabilities,IdmefMessageFactory.newregistration);
    event=factory.newEvent(reg);
    getBlackboardService().openTransaction();
    getBlackboardService().publishAdd(event);
    getBlackboardService().closeTransaction();
      
    log.debug("Success in publishing  capabilities in Test Dummy sensor  :");
   
    capabilities = new ArrayList();
    capabilities.add( imessage.createClassification( "POD", null  ) );
    capabilities.add( imessage.createClassification( "JarVerification", null  ) );
    
    reg=imessage.createRegistrationAlert(sensor,capabilities,IdmefMessageFactory.removefromregistration);
    event=factory.newEvent(reg);
    getBlackboardService().openTransaction();
    getBlackboardService().publishAdd(event);
      /* getBlackboardService().closeTransaction();
      newevents=new String[1];
      neworigins=new String[1]; 
       newevents[0]="POD";
       //newevents[0]="JarVerification";
      neworigins[0]="Classification.VENDOR_SPECIFIC";
      // neworigins[1]="Classification.VENDOR_SPECIFIC";
       sensor=new DummySensor("sensor1");
      reg=imessage.createRegistrationAlert(sensor,newevents,neworigins,IdmefMessageFactory.removefromregistration);
      event=factory.newEvent(reg);
      getBlackboardService().openTransaction();
      getBlackboardService().publishAdd(event);
      */
    
  }
          
       
  protected void execute () {
    // process unallocated tasks
	

  }
}
