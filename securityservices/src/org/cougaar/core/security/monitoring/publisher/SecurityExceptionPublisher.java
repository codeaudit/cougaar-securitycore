/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

package org.cougaar.core.security.monitoring.publisher;

// cougaar core classes
import org.cougaar.core.security.constants.IdmefClassifications;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.SecurityExceptionEvent;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.services.auth.SecurityContextService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Alert;


public class SecurityExceptionPublisher extends IdmefEventPublisher {

  public SecurityExceptionPublisher(BlackboardService bbs, SecurityContextService scs, 
    CmrFactory cmrFactory, LoggingService logger, SensorInfo info, ThreadService ts) {
    super(bbs, scs, cmrFactory, logger, info, ts);
  }

  private List createClassifications(String classification) {
    ArrayList cfs = new ArrayList();
    if(classification.equals(IdmefClassifications.SECURITY_MANAGER_EXCEPTION)) {
      cfs.add(SecurityExceptionEvent.SECURITY_MGR_EXCEPTION); 
    }
    else {
      cfs.add(SecurityExceptionEvent.JAR_VERIFY_FAILURE); 
    }
    return cfs;
  }

  protected Event createIDMEFAlert(FailureEvent event) {
    if(event == null || !(event instanceof SecurityExceptionEvent)) {
      return null;
    }
    
    SecurityExceptionEvent see = (SecurityExceptionEvent)event;
    Principal [] principals = see.getPrincipals();
    String stackTrace = see.getStackTrace();
    ArrayList additionalData = new ArrayList();
    
    if(principals != null) {
      // add the principal information to the additionalData
   	  for(int i = 0; i < principals.length; i++) {
        AdditionalData data = _idmefFactory.createAdditionalData(AdditionalData.STRING, 
                                                                 SecurityExceptionEvent.PRINCIPAL_ID, 
                                                                 principals[i].toString());
        additionalData.add(data);
      }
    }
    
    if(stackTrace != null ){
      // add the stack trace to the additionalData
     	AdditionalData data = _idmefFactory.createAdditionalData(AdditionalData.STRING, 
     	                                                         SecurityExceptionEvent.STACKTRACE_ID, 
     	                                                         stackTrace);
    	additionalData.add(data);
    }

    Alert alert = _idmefFactory.createAlert(_sensorInfo, 
                                            see.getDetectTime(), // get the event detect time
                                            null, // source is null for now
                                            null, // target is null for now
                                            createClassifications(see.getClassification()),
                                            additionalData);
    return _cmrFactory.newEvent(alert); 
  }
  
}
