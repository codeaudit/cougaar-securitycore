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

import org.cougaar.core.security.constants.IdmefClassifications;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.SecurityExceptionEvent;
import org.cougaar.core.security.monitoring.publisher.EventPublisher;
import org.cougaar.core.security.monitoring.publisher.SecurityExceptionPublisher;
import org.cougaar.core.service.ThreadService;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Observable;
import java.util.Observer;

public class BootStrapEventPlugin extends SensorPlugin implements Observer {  
  /*
  private Condition sensorCondition;
  private int numberOfEvents = 0;
  */
  private SensorInfo _sensorInfo;
  private ThreadService _threadService;
  private final  String[] CLASSIFICATIONS = { IdmefClassifications.SECURITY_MANAGER_EXCEPTION,
                                              IdmefClassifications.JAR_VERIFICATION_FAILURE };
  
  protected synchronized void setupSubscriptions() {
    super.setupSubscriptions();
    // sensorCondition = new BootstrapEventCondition(numberOfEvents);
    //_blackboard.publishAdd(sensorCondition);
    EventPublisher publisher = new SecurityExceptionPublisher(_blackboard, _scs, _cmrFactory, _log, getSensorInfo(), _threadService);
    setPublisher(publisher);
    // initialize the publisher
    publishIDMEFEvent();
    // register this observer with the security manager
    registerForEvents();
  }
  
  protected void execute() {
  }

  public void setThreadService(ThreadService ts) {
    _threadService = ts;
  }

  protected SensorInfo getSensorInfo() {
    if(_sensorInfo == null) {
      _sensorInfo = new BootstrapSensorInfo();  
    } 
    return _sensorInfo;
  }
  
  public static void publishEvent(FailureEvent event) {
    publishEvent(BootStrapEventPlugin.class, event);
  }
  
  public void update(Observable o, Object arg) {
    ArrayList eventList =(ArrayList)arg;
    Iterator i = eventList.iterator();
    while(i.hasNext()) {
      Object obj = i.next();
      FailureEvent event = createSecurityExceptionEvent(obj);
      if(event != null) {
        publishEvent(event);
      }
    } 
  }
  
  public FailureEvent createSecurityExceptionEvent(Object o) {
    Class c = o.getClass();
    String fqcn = c.getName();
    
    if(fqcn.equals("org.cougaar.core.security.securebootstrap.BootstrapEvent")) {
      try {
        // get the classification for this event
      	Field f = c.getDeclaredField("classification");
      	String classification = (String)f.get(o);
      	// get the detection time
      	f = c.getDeclaredField("detecttime");
      	Date detectTime =(Date)f.get(o);
      	// get the principals
      	f = c.getDeclaredField("principals");
      	Principal[] principals = (Principal[])f.get(o);
      	// get the stack trace for the event
      	f = c.getDeclaredField("subjectStackTrace");
      	String stackTrace = (String)f.get(o);
      	return new SecurityExceptionEvent(null, // source null for now
      	                                  null, // target null for now
      	                                  null, // reason null for now
      	                                  null, // data null for now
      	                                  classification, 
      	                                  principals, 
      	                                  stackTrace, 
      	                                  detectTime);
      }
      catch (Exception exp) {
	      exp.printStackTrace();
      }
    }
    return null;
  }
  
  public void registerForEvents() {
    //System.out.println(" In register method:");
    SecurityManager sm = System.getSecurityManager();
    //System.out.println(" Class is :"+sm.getClass().getName());
    Class [] classes = new Class[0];
    Method method = null;
    try {
      method = sm.getClass().getMethod("getMREventQueue",null);
    }
    catch (Exception e) {
      e.printStackTrace();
    }
    Object ob = null;
    try {
      Object[] args = {};
      ob = method.invoke(sm,args);
      Class [] param = {Observer.class};
      method = ob.getClass().getMethod("register",param);
      Object oobj = null;
      if(_log.isDebugEnabled()) {
        _log.debug(" observer being passed is : " + this.toString());
      }
      Object[] argss = {this};
      oobj = method.invoke(ob,argss);
    }
    catch(Exception iexp) {
      iexp.printStackTrace();
    }
  }
  
  protected String []getClassifications() {
    return CLASSIFICATIONS;
  }
  
  protected boolean agentIsTarget() {
    return true;
  }
  
  protected boolean agentIsSource() {
    return false;
  }
  
  private class BootstrapSensorInfo implements SensorInfo {
    
    public String getName(){
      return "BootStrapEventSensor";
    }
    
    public String getManufacturer(){
      return "CSI";
    }

    public String getModel(){
      return "Cougaar";
    }
    public String getVersion(){
      return "1.0";
    }
    public String getAnalyzerClass(){
      return "Security Analyzer";
    }
  } 
 
  /*
  // This condition is used to test the adaptivity engine
  // A realistic condition should be developed.
  static class BootstrapEventCondition
    implements Condition
  {
    Double _rate;
    static final OMCRangeList RANGE = 
      new OMCRangeList(new Double(0.0), new Double(Integer.MAX_VALUE));

    public BootstrapEventCondition(int rate) {
      _rate = new Double((double) rate);
    }
    
    public OMCRangeList getAllowedValues() {
      return RANGE;
    }
    
    public String getName() {
      return "org.cougaar.core.security.monitoring.BOOTSTRAP_EVENT";
    }

    public Comparable getValue() {
      return _rate;
    }
    public void setValue(int rate) {
    }
  }
  */
}
