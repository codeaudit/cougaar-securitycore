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
import org.cougaar.multicast.AttributeBasedAddress;

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
import java.util.Collection;

import edu.jhuapl.idmef.*;


public class TestDummySensorPlugin  extends  ComponentPlugin   {
  private LoggingService log;
  private DomainService domainService = null;
  private String mgrrole=null;
  private AttributeBasedAddress mgrAddress;
  private String sensor_name=null;
  private String dest_community=null;
  private Object param;
  private String[] givecapabilities;
    
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

   public void setParameter(Object o){
    this.param=o;
  }

  public java.util.Collection getParameters() {
    return (Collection)param;
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
    Collection col=getParameters();
    if(col.size()>3) {
      log.debug("setupSubscriptions of TestDummy sensorPlugin called  too many parameters :"); 
    }
    if(col.size()!=0){
      String params[]=new String[1];
      String parameters[]=(String[])col.toArray(new String[0]);
      mgrrole=parameters[0];
      sensor_name=parameters[1];
      dest_community=parameters[2];
      
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    TestDummySensor sensor=new TestDummySensor (sensor_name);
    CmrRelay relay=null;
    List capabilities = new ArrayList();
   
    capabilities.add( imessage.createClassification( "POD", null  ) );
    capabilities.add( imessage.createClassification( "TCPSCAN", null  ) );
    capabilities.add( imessage.createClassification( "LOGINFAILURE", null  ) );
   
    RegistrationAlert reg=imessage.createRegistrationAlert(sensor,capabilities,IdmefMessageFactory.newregistration,IdmefMessageFactory.SensorType);
    
    NewEvent event=factory.newEvent(reg);
    log.debug(" going to publish capabilities in Test Dummy sensorplugin  1:");
    mgrAddress=new AttributeBasedAddress(dest_community,"Role",mgrrole);
    relay = factory.newCmrRelay(event,mgrAddress);
    getBlackboardService().publishAdd(relay);
    //getBlackboardService().closeTransaction();
    // TestDummySensor sensor=new TestDummySensor (sensor_name+1);
    // capabilities.add( imessage.createClassification( "SecurityException", null  ) );
    // capabilities.add( imessage.createClassification( "JarException", null  ) );
   
  }
          
       
  protected void execute () {
    // process unallocated tasks
	

  }
}
