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
import java.util.Collection;
import java.lang.reflect.*;
import java.security.Principal;

// Cougaar core infrastructure
import org.cougaar.core.adaptivity.Condition;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.OMCThruRange;
import org.cougaar.core.component.*;
import org.cougaar.core.agent.*;
import org.cougaar.core.service.community.*;
// Cougaar security services
//import org.cougaar.core.security.securebootstrap.EventHolder;
import org.cougaar.core.security.securebootstrap.BootstrapEvent;

// Cougaar overlay
import org.cougaar.core.security.constants.IdmefClassifications;

import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.adaptivity.OperatingModeImpl;

// Security services
import org.cougaar.core.security.securebootstrap.CougaarSecurityManager;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;
import  org.cougaar.core.security.securebootstrap.BootstrapEvent;

import edu.jhuapl.idmef.*;

public class BootStrapEventPlugin extends SensorPlugin  implements Observer  {
  
  //private EventHolder eventholder=null;
  private Condition sensorCondition;
  private int numberOfEvents = 0;
  private OperatingMode dummyOP = null;
  private static final String DUMMY_OP =
    "org.cougaar.core.security.monitoring.DUMMY_OP";
  private static final OMCRangeList DUMMY_OP_RANGE =
      new OMCRangeList(new OMCThruRange(1.0, Double.MAX_VALUE ));
  private SensorInfo m_sensorInfo;
  private final  String[] CLASSIFICATIONS = {IdmefClassifications.SECURITY_MANAGER_EXCEPTION,IdmefClassifications.JAR_VERIFICATION_FAILURE};
  private boolean openTransaction=false; 
  /**
   * subscribe to
   */
  protected synchronized void setupSubscriptions() {
    // For test purposes
    
    super.setupSubscriptions();
    /* Fix for nested open transaction
       openTransaction=true;
     */
    sensorCondition = new BootstrapEventCondition(numberOfEvents);
    m_blackboard.publishAdd(sensorCondition);

    registerforEvents();
   
    // Dummy operating mode
    dummyOP = new OperatingModeImpl(DUMMY_OP, 
				    DUMMY_OP_RANGE, 
				    new Double(5));
    m_blackboard.publishAdd(dummyOP);
    /*
      Fix for nested open transaction
      openTransaction=false;
    */
  }
  
  protected void execute() {

  }
  protected SensorInfo getSensorInfo() {
    if(m_sensorInfo == null) {
      m_sensorInfo = new BootstrapSensorInfo();  
    } 
    return m_sensorInfo;
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
	m_log.debug(" Got event after reconstruction :"+event.toString());
      }
      else {
        if(m_log.isDebugEnabled()) 
          m_log.debug(" Got event as null in update of event Service :");
      }
    }
    if(!events.isEmpty()) {
      publishIDMEFEvent(events);
    }
    
  }
  public synchronized void publishIDMEFEvent(Vector vectorofevents) {
    /*BlackboardService bbservice=null;
    DomainService dservice=null;
    */
     m_blackboard=getBlackboardService();
     m_domainService=getDomainService();
    // bbservice=(BlackboardService)serviceBroker.getService(this,BlackboardService.class,null);
    if( m_blackboard==null) {
      m_log.error(" error cannot get BlackBoard Service:");
    }
    // domainservice=(DomainService)serviceBroker.getService(this,DomainService.class,null);
    if(m_domainService==null) {
       m_log.error(" error cannot get domain service Going to loose all events :");
    }
    CmrFactory factory=(CmrFactory)m_domainService.getFactory("cmr");
    IdmefMessageFactory imessage=null;
    if(factory!=null) {
      imessage=factory.getIdmefMessageFactory();
    }
    if(imessage==null) {
       m_log.error(" error cannot get Idmef message factory :");
    }
    Classification classification =null;
    BootstrapEvent event=null;
    AdditionalData adddata=null;
    boolean myopenTransaction=false;
    m_blackboard.openTransaction();
    for(int cnt=0;cnt<vectorofevents.size();cnt++) {
      event=(BootstrapEvent)vectorofevents.elementAt(cnt);
      classification= imessage.createClassification(event.classification,
				    null,
				    Classification.VENDOR_SPECIFIC);
      ArrayList classifications = new ArrayList(1);
      classifications.add(classification);
      ArrayList targets = new ArrayList(1);
      ArrayList sources=new ArrayList(1);
      DetectTime detecttime=new DetectTime();
      detecttime.setIdmefDate(event.detecttime);
       ArrayList data = new ArrayList();
      if(event.principals!=null) {
	/*
	adddata=imessage.createAdditionalData();
	adddata.setType(AdditionalData.STRING);
	*/
	StringBuffer buff=new StringBuffer();
	for(int i=0;i<event.principals.length;i++) {
	  buff.append(event.principals[i].toString()+"\n");
	}
//	adddata.setAdditionalData(buff.toString());
	adddata = imessage.createAdditionalData(AdditionalData.STRING,"PRINCIPAL_INFO", buff.toString());
	data.add(adddata);
      }
      if(event.subjectStackTrace!=null){
	adddata=imessage.createAdditionalData(AdditionalData.STRING, "STACK_TRACE", event.subjectStackTrace);
	/*
	adddata.setType(AdditionalData.STRING);
	adddata.setAdditionalData(event.subjectStackTrace);
	*/
	data.add(adddata);
      }
      Alert alert = imessage.createAlert(getSensorInfo(), detecttime,
				       sources, targets,
				       classifications, data);
      Event e = factory.newEvent(alert);
      m_log.debug("Intrusion Alert:" + alert.toString());
      //System.out.println("Publishing sensor Event :");
      
      //bbservice.openTransaction();
      if(m_log.isDebugEnabled()) {
	m_log.debug("Publishing alert: " + alert);
      }
       m_blackboard.publishAdd(e);
      
      // Increment the total number of events
      numberOfEvents++;
      ((BootstrapEventCondition)sensorCondition).setValue(numberOfEvents);
     
       m_blackboard.publishChange(sensorCondition);
       // bbservice.closeTransaction();
    }
    /* Fix for nested open transaction
      if(myopenTransaction) {
      openTransaction=false;
    */
      m_blackboard.closeTransaction();
      // }
    
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
      if(m_log.isDebugEnabled())
        m_log.debug(" observer being passed is :"+this.toString());
      Object[] argss={this};
      oobj=method.invoke(ob,argss);
    }
     catch(Exception iexp) {
     iexp.printStackTrace();
    }
    
  }
  
  /*
  public void registercapabilities() {
    
    BlackboardService bbservice=getBlackboardService();
    DomainService dservice=getDomainService();
    if(bbservice==null) {
      m_log.error(" error cannot get BlackBoard Service:");
      return;
    }
    //domainservice=(DomainService)serviceBroker.getService(this,DomainService.class,null);
    if(dservice==null) {
       m_log.error(" error cannot get domain service Going to loose all events :");
       return;
    }
    CmrFactory factory=(CmrFactory)dservice.getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    List capabilities = new ArrayList();
    capabilities.add( imessage.createClassification( IdmefClassifications.SECURITY_MANAGER_EXCEPTION ,
						     null,
						     Classification.VENDOR_SPECIFIC  ) );
    capabilities.add( imessage.createClassification( IdmefClassifications.JAR_VERIFICATION_FAILURE, null,
						     Classification.VENDOR_SPECIFIC  ) );
    List sources=new ArrayList();
    List targets=new ArrayList();
    List additionaldatas=new ArrayList();
    Target target=imessage.createTarget(imessage.getNodeInfo(),imessage.getUserInfo(),imessage.getProcessInfo(),null,null,null);
    org.cougaar.core.security.monitoring.idmef.Agent agentinfo=imessage.getAgentInfo();
    String [] ref=null;
    if(agentinfo.getRefIdents()!=null) {
      String[] originalref=agentinfo.getRefIdents();
      ref=new String[originalref.length+1];
      System.arraycopy(originalref,0,ref,0,originalref.length);
      ref[originalref.length]=target.getIdent();
    }
    else {
      ref=new String[1];
      ref[0]=target.getIdent();
    }
    agentinfo.setRefIdents(ref);
    AdditionalData additionaldata=imessage.createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.TARGET_MEANING,agentinfo);
    targets.add(target);
    additionaldatas.add(additionaldata);
    RegistrationAlert reg=imessage.createRegistrationAlert(this,
							   sources,
							   targets,
							   capabilities,
							   additionaldatas,
							   IdmefMessageFactory.newregistration,
							   IdmefMessageFactory.SensorType,
							   myAddress.toString());
     NewEvent event=factory.newEvent(reg);
      if(m_log.isDebugEnabled())
        m_log.debug(" going to publish capabilities in event Service  :");
    CmrRelay  relay ;
    relay= factory.newCmrRelay(event,mgrAddress);
    //relay= factory.newCmrRelay(event,destcluster);
    //getBlackboardService().publishAdd(relay);
    bbservice.publishAdd(relay); 
    
  }
  */
  
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
}
