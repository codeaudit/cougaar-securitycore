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
import org.cougaar.core.security.securebootstrap.EventHolder;
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

public class BootStrapEventPlugin extends ComponentPlugin  implements Observer, SensorInfo  {
  
  private EventHolder eventholder=null;
  private DomainService domainService = null;
  private CommunityService communityService=null; 
  private String mgrrole=null;
  private AttributeBasedAddress mgrAddress;
  private String sensor_name=null;
  private String dest_community=null;
  //private ClusterIdentifier destcluster;
  //private String dest_agent;
  private LoggingService log; 
  //private String mgrrole=null;
  private MessageAddress myAddress;
  // For test purposes
  private Condition sensorCondition;
  private int numberOfEvents = 0;
  private OperatingMode dummyOP = null;
  private static final String DUMMY_OP =
    "org.cougaar.core.security.monitoring.DUMMY_OP";
  private static final OMCRangeList DUMMY_OP_RANGE =
      new OMCRangeList(new OMCThruRange(1.0, Double.MAX_VALUE ));

  public void setDomainService(DomainService aDomainService) {
    domainService = aDomainService;
  }
  
  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
  }
  
  public void setCommunityService(CommunityService cs) {
    //System.out.println(" set community services Servlet component :");
     this.communityService=cs;
   }
  
  /**
   * subscribe to
   */
  protected void setupSubscriptions() {
    log = (LoggingService)
      getBindingSite().getServiceBroker().getService(this,
						     LoggingService.class, null);

    BlackboardService bbservice=getBlackboardService();
    DomainService service=getDomainService();
    if((service==null)|| (bbservice==null)){
      log.error("Unusual error either bbservice or domain service is null:");
      
    }
    // For test purposes
    sensorCondition = new BootstrapEventCondition(numberOfEvents);
    bbservice.publishAdd(sensorCondition);

    myAddress = getBindingSite().getAgentIdentifier();
    log.debug("setupSubscriptions of  called for BootStrapSensor Plugin in  :"+ myAddress.toString()); 
    String mySecurityCommunity= getMySecurityCommunity();
    log.debug(" BootStrapSensor My security community :"+mySecurityCommunity +" agent name :"+myAddress.toString());  
    if(mySecurityCommunity==null) {
      log.error("No Info about My  SecurityCommunity : returning Cannot continue !!!!!!"+myAddress.toString());  
      return;
    }
    else {
      String myRole=getMyRole(mySecurityCommunity);
      log.debug(" My Role is  :"+myRole +" agent name :"+myAddress.toString()); 
      if(myRole.equalsIgnoreCase("Member")) {
	mgrrole="SecurityMnRManager-Enclave";
	dest_community=mySecurityCommunity;
      }
      if((myRole.equalsIgnoreCase("SecurityMnRManager-Enclave")) &&(this instanceof SensorInfo)) {
	mgrrole="SecurityMnRManager-Enclave";
	dest_community=mySecurityCommunity;
      }
      log.debug(" My destination community is  :"+dest_community +" agent name :"+myAddress.toString());
      if(mgrrole!=null) {
	mgrAddress=new AttributeBasedAddress(dest_community,"Role",mgrrole);
	//mgrAddress=new MessageAddress("Tiny1ADEnclaveSecurityManager");
	log.debug("Created  manager address :"+ mgrAddress.toString() +" in  BootStrapSensor plugin at :"+myAddress.toString());
	registercapabilities();
      }
    }
    //registercapabilities();
    registerforEvents();
   
    // Dummy operating mode
    dummyOP = new OperatingModeImpl(DUMMY_OP, 
				    DUMMY_OP_RANGE, 
				    new Double(5));
    bbservice.publishAdd(dummyOP);
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
        if(log.isDebugEnabled()) 
          log.debug(" Got event as null in update of event Service :");
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
      log.error(" error cannot get BlackBoard Service:");
    }
    // domainservice=(DomainService)serviceBroker.getService(this,DomainService.class,null);
    if(dservice==null) {
       log.error(" error cannot get domain service Going to loose all events :");
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

      // Increment the total number of events
      numberOfEvents++;
      ((BootstrapEventCondition)sensorCondition).setValue(numberOfEvents);
      bbservice.publishChange(sensorCondition);
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
      if(log.isDebugEnabled())
        log.debug(" observer being passed is :"+this.toString());
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
      log.error(" error cannot get BlackBoard Service:");
      return;
    }
    //domainservice=(DomainService)serviceBroker.getService(this,DomainService.class,null);
    if(dservice==null) {
       log.error(" error cannot get domain service Going to loose all events :");
       return;
    }
    CmrFactory factory=(CmrFactory)dservice.getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    List capabilities = new ArrayList();
    capabilities.add( imessage.createClassification( IdmefClassifications.SECURITY_MANAGER_EXCEPTION ,
						     "http://www.cougaar.org/security/SecurityManagerAlarm.html",
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
      if(log.isDebugEnabled())
        log.debug(" going to publish capabilities in event Service  :");
    CmrRelay  relay ;
    relay= factory.newCmrRelay(event,mgrAddress);
    //relay= factory.newCmrRelay(event,destcluster);
    //getBlackboardService().publishAdd(relay);
    bbservice.publishAdd(relay); 
    
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
  
  private String getMySecurityCommunity() {
    String mySecurityCommunity=null;
    if(communityService==null) {
     log.error(" Community Service is null" +myAddress.toString()); 
    }
    String filter="(CommunityType=Security)";
    Collection securitycom=communityService.listParentCommunities(myAddress.toString(),filter);
    if(!securitycom.isEmpty()) {
      if(securitycom.size()>1) {
	log.warn("Belongs to more than one Security Community " +myAddress.toString());  
	return mySecurityCommunity;
      }
      String [] securitycommunity=new String[1];
      securitycommunity=(String [])securitycom.toArray(new String[1]);
      mySecurityCommunity=securitycommunity[0];
    }
    else {
      	log.warn("Search  for my Security Community FAILED !!!!" +myAddress.toString()); 
    }
    
    return mySecurityCommunity;
  }
  
  private String getMyRole(String mySecurityCommunity) {
    String myRole=null;
    boolean enclavemgr=false;
    boolean societymgr=false;
    boolean member=false;
    if(communityService==null) {
      log.error(" Community Service is null" +myAddress.toString()); 
    }
    Collection roles =communityService.getEntityRoles(mySecurityCommunity,myAddress.toString());
    Iterator iter=roles.iterator();
    String role;
    while(iter.hasNext()) {
      role=(String)iter.next();
      log.debug(" Roles for agent :"+ myAddress.toString() +"community :"+ mySecurityCommunity+
		"role :"+role);
      if(role.equalsIgnoreCase("SecurityMnRManager-Enclave")) {
	enclavemgr=true;
      }
      else if(role.equalsIgnoreCase("SecurityMnRManager-Society")) {
	societymgr=true;
      }
      else if(role.equalsIgnoreCase("Member")) {
	member=true;
      }
    }
    if(member){
      myRole="Member";
    }
    else if(enclavemgr) {
      myRole="SecurityMnRManager-Enclave"; 
    }
    else if(societymgr) {
      myRole="SecurityMnRManager-Society";
    }
    log.debug(" returning !!!!! role :"+myRole);
    return myRole;
    						      
  }
  
  public String getDestinationCommunity(String myrole) {
    if(communityService==null) {
      log.error(" Community Service is null" +myAddress.toString()); 
    }
    String destrole=null;
    if(myrole.equalsIgnoreCase("member")) {
      destrole="SecurityMnRManager-Enclave";
    }
    else if(myrole.equalsIgnoreCase("SecurityMnRManager-Enclave")) {
      destrole="SecurityMnRManager-Society";
    }
    String filter="(CommunityType=Security)";
    Collection securitycol=communityService.search(filter);
    Iterator itersecurity=securitycol.iterator();
    String comm=null;
    while(itersecurity.hasNext()) {
      comm=(String)itersecurity.next();
      Collection societysearchresult=communityService.searchByRole(comm,destrole);
      if(societysearchresult.isEmpty()) {
	continue;
      }
      else {
	if(societysearchresult.size()>1) {
	   log.error(" Too many Society Manager " +myAddress.toString());
	   return null;
	}
	break;
      }
    }
    return comm;
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
