/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

import java.util.Observer;
import java.util.Observable;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.Iterator;
import java.util.Date;
import java.lang.reflect.*;
import java.security.Principal;

import org.cougaar.core.security.securebootstrap.EventHolder;
import org.cougaar.core.security.securebootstrap.BootstrapEvent;
import org.cougaar.core.component.*;
import org.cougaar.core.agent.*;
/*
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceAvailableListener;
*/
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.plugin.ComponentPlugin;

import org.cougaar.core.security.securebootstrap.CougaarSecurityManager;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;
import  org.cougaar.core.security.securebootstrap.BootstrapEvent;

import edu.jhuapl.idmef.*;



public class BootStrapEventPlugin extends ComponentPlugin  implements Observer, SensorInfo  {
  
  private EventHolder eventholder=null;
  private DomainService domainService = null;

  public void setDomainService(DomainService aDomainService) {
    domainService = aDomainService;
  }
  
  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
  }


  /**
   * subscribe to
   */
  protected void setupSubscriptions() {
    BlackboardService bbservice=getBlackboardService();
     DomainService service=getDomainService();
    if((service==null)|| (bbservice==null)){
      System.out.println(" Unusual error either bbservice or domain service is null:");
      
    }
    //System.out.println(" Going to register with event Holder from  setupSubscriptions ===========>: This is Event Service:");
    registercapabilities();
    registerforEvents();
   
    
  }
  
  protected void execute() {

  }
 
  public void update(Observable o, Object arg) {
    // System.out.println(" New M&R boot strap events :");
    ArrayList eventList=(ArrayList)arg;
    Iterator iterator= eventList.iterator();
    BootstrapEvent event=null;
    Object obj=null;
    Vector events=new Vector();
    while(iterator.hasNext())  {
      obj=iterator.next();
      event=constructbootstrapevent(obj);
      if(event!=null) {
	events.add(event);
	//System.out.println(" Got event after reconstruction :"+event.toString());
      }
      else {
	System.out.println(" Got event as null in update of event Service :");
      }
    }
    if(!events.isEmpty()) {
      publishIDMEFEvent(events);
    }
    
  }
  public void publishIDMEFEvent(Vector vectorofevents) {
    BlackboardService bbservice=null;
    DomainService dservice=null;
    bbservice=getBlackboardService();
    dservice=getDomainService();
    // bbservice=(BlackboardService)serviceBroker.getService(this,BlackboardService.class,null);
    if(bbservice==null) {
      System.out.println(" error cannot get BlackBoard Service:");
    }
    // domainservice=(DomainService)serviceBroker.getService(this,DomainService.class,null);
    if(dservice==null) {
       System.out.println(" error cannot get domain service Going to loose all events :");
    }
    CmrFactory factory=(CmrFactory)dservice.getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    Classification classification =null;
    BootstrapEvent event=null;
    AdditionalData adddata=null;
    for(int cnt=0;cnt<vectorofevents.size();cnt++) {
      event=(BootstrapEvent)vectorofevents.elementAt(cnt);
      classification= imessage.createClassification(event.classification,
				    "http://www.cougaar.org",
				    Classification.VENDOR_SPECIFIC);
      ArrayList classifications = new ArrayList(1);
      classifications.add(classification);
      ArrayList targets = new ArrayList(1);
      ArrayList sources=new ArrayList(1);
      DetectTime detecttime=new DetectTime();
      detecttime.setIdmefDate(event.detecttime);
       ArrayList data = new ArrayList();
      if(event.principals!=null) {
	adddata=new AdditionalData();
	adddata.setType(AdditionalData.STRING);
	StringBuffer buff=new StringBuffer();
	for(int i=0;i<event.principals.length;i++) {
	  buff.append(event.principals[i].toString()+"\n");
	}
	adddata.setAdditionalData(buff.toString());
	data.add(adddata);
      }
      if(event.subjectStackTrace!=null){
	adddata=new AdditionalData();
	adddata.setType(AdditionalData.STRING);
	adddata.setAdditionalData(event.subjectStackTrace);
	data.add(adddata);
      }
      Alert alert = imessage.createAlert(this, detecttime,
				       sources, targets,
				       classifications, data);
      Event e = factory.newEvent(alert);
      //System.out.println("Intrusion Alert:" + alert.toString());
      //System.out.println("Publishing sensor Event :");
      bbservice.publishAdd(e);

    }
     
    
  }
  public BootstrapEvent constructbootstrapevent(Object o) {
    String completeclassname=o.getClass().getName();
    String classname=null;
    if(completeclassname!=null) {
      int index=completeclassname.lastIndexOf('.');
      classname=completeclassname.substring(index+1,completeclassname.length());
      //System.out.println(" Got class name as ================>>"+classname);
    }
    else {
      //System.out.println(" Got class name as ==================>>NULL");
    }
    if(classname.equals("BootstrapEvent")) {
      //System.out.println(" got bootstrap event object trying to reconstruct :");
      try {
	Class bootstrap=o.getClass();
	Field fld=bootstrap.getDeclaredField("classification");
	String classification=(String)fld.get(o);
	//System.out.println(" got classification as =====>:"+classification);
	fld=bootstrap.getDeclaredField("detecttime");
	Date date=(Date)fld.get(o);
	//System.out.println(" got Date as =====>:"+date);
	fld=bootstrap.getDeclaredField("principals");
	Principal[] principals=(Principal[])fld.get(o);
	fld=bootstrap.getDeclaredField("subjectStackTrace");
	String stacktrace=(String)fld.get(o);
	//System.out.println(" got stacktrace as =====>:"+stacktrace);
	return new BootstrapEvent(classification,date,principals,stacktrace);
      }
      catch (Exception exp) {
	exp.printStackTrace();
      }
    }
    // System.out.println(" new without value got boot strap event:");   
       return null;
  }
  public void registerforEvents() {
    //System.out.println(" In register method:");
    SecurityManager sm =System.getSecurityManager();
    //System.out.println(" Class is :"+sm.getClass().getName());
    Class [] classes=new Class[0];
    Method method=null;
    try {
      method=sm.getClass().getMethod("getMREventQueue",null);
    }
    catch (Exception e) {
      e.printStackTrace();
    }
    Object ob= null;
    try {
      Object[] args={};
      ob=method.invoke(sm,args);
      Class [] param={Observer.class};
      method=ob.getClass().getMethod("register",param);
       Object oobj=null;
       System.out.println(" observer being passed is :"+this.toString());
       Object[] argss={this};
       oobj=method.invoke(ob,argss);
    }
     catch(Exception iexp) {
     iexp.printStackTrace();
    }
    
  }
  

  public void registercapabilities() {
    
    BlackboardService bbservice=getBlackboardService();
    DomainService dservice=getDomainService();
    if(bbservice==null) {
      System.out.println(" error cannot get BlackBoard Service:");
      return;
    }
    //domainservice=(DomainService)serviceBroker.getService(this,DomainService.class,null);
    if(dservice==null) {
       System.out.println(" error cannot get domain service Going to loose all events :");
       return;
    }
    CmrFactory factory=(CmrFactory)dservice.getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    List capabilities = new ArrayList();
    capabilities.add( imessage.createClassification( "Cougaar.security.nai."+BootstrapEvent.SecurityAlarm ,
						     "http://www.cougaar.org/security/SecurityManagerAlarm.html",
						     Classification.VENDOR_SPECIFIC  ) );
    capabilities.add( imessage.createClassification( "Cougaar.security.nai."+BootstrapEvent.JarVerificationAlarm, null,
						     Classification.VENDOR_SPECIFIC  ) );
     // no need to specify targets since we may not know of the targets
    RegistrationAlert reg=
      imessage.createRegistrationAlert(this,
				       capabilities,IdmefMessageFactory.newregistration);
     NewEvent event=factory.newEvent(reg);
     System.out.println(" going to publish capabilities in event Service  :");
    bbservice.publishAdd(event); 
    
  }
   public String getName(){
    return "BootStrapEventSensor";
  }
  public String getManufacturer(){
    return "NAI Labs";
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
