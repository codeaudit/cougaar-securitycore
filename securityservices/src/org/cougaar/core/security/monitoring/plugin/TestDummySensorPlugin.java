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
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.core.service.*;
import org.cougaar.core.service.community.*;
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;

import org.cougaar.core.agent.ClusterIdentifier;

import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;
import edu.jhuapl.idmef.*;


public class TestDummySensorPlugin  extends  ComponentPlugin   {
  private LoggingService log;
  private DomainService domainService = null;
  private CommunityService communityService=null;
  private String mgrrole=null;
  private AttributeBasedAddress mgrAddress;
  //private MessageAddress mgrAddress;
  private MessageAddress myAddress;
  private ClusterIdentifier destcluster;
  private String sensor_name="SensorTest";
  private String dest_community=null;
  private Object param;
  private String dest_agent;
  
    
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
  
  public void setCommunityService(CommunityService cs) {
    //System.out.println(" set community services Servlet component :");
     this.communityService=cs;
   }
   
  protected void setupSubscriptions() {
    
    log = (LoggingService)
      getBindingSite().getServiceBroker().getService(this,
						     LoggingService.class, null);
    myAddress = getBindingSite().getAgentIdentifier();
    log.debug("setupSubscriptions of  called for TestDummySensor Plugin in  :"+ myAddress.toString()); 
    DomainService service=getDomainService();
    if(service==null) {
      log.debug(" Got service as null in Test Dummy Sensor  :");
      return;
    }
    String mySecurityCommunity= getMySecurityCommunity();
    log.debug(" TestDummy sensor My security community :"+mySecurityCommunity +" agent name :"+myAddress.toString());  
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
      /*
      else if(myRole.equalsIgnoreCase("SecurityMnRManager-Society")) ) {
	mgrrole="SecurityMnRManager-Enclave";
	dest_community=getDestinationCommunity(myRole);
	if(dest_community==null) {
	  log.error("Cannot get Destination community in agent  !!!!!!"+myAddress.toString()
		    +"\nmy Role is "+ myRole+
		    "\nCannot continue RETURNING !!!!!!!!!!!!!!!");
	  return;
	}
      }
      */
      log.debug(" My destination community is  :"+dest_community +" agent name :"+myAddress.toString());
      mgrAddress=new AttributeBasedAddress(dest_community,"Role",mgrrole);
      //mgrAddress=new MessageAddress("Tiny1ADEnclaveSecurityManager");
      log.debug("###############$$$$$$$$$$$$$$$$$$$$$$$$$$#######$$$$$$$$$$$$$$$$$$$$$########################################################################################################################## Created  manager address :"+ mgrAddress.toString());
    }
    
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    TestDummySensor sensor=new TestDummySensor (sensor_name);
    CmrRelay relay=null;
    List capabilities = new ArrayList();
   
    capabilities.add( imessage.createClassification( "POD", null  ) );
    capabilities.add( imessage.createClassification( "TCPSCAN", null  ) );
    capabilities.add( imessage.createClassification( "LOGINFAILURE", null  ) );
   
    RegistrationAlert reg=imessage.createRegistrationAlert(sensor,capabilities,
							   IdmefMessageFactory.newregistration,
							   IdmefMessageFactory.SensorType);
    
    NewEvent event=factory.newEvent(reg);
    if(log.isDebugEnabled()) {
    log.debug(" going to publish capabilities in Test Dummy sensorplugin  1:");
    log.debug(" going to publish capabilities in TestDummySensorplugin from :"+myAddress.toString()
		       +" Capabilities are :"+reg.toString() );
    }
    //mgrAddress=new AttributeBasedAddress(dest_community,"Role",mgrrole);
    if(log.isDebugEnabled())
      log.debug(" destination ABA address is :"+mgrAddress.toString());
    relay = factory.newCmrRelay(event,mgrAddress);
    getBlackboardService().publishAdd(relay);
    if(log.isDebugEnabled()) {
      log.debug("From testDummysensorPlugin :"+ myAddress.toString() +"  relay is :"+relay.toString());
      log.debug(" Going to dump targets :");
      Set targets =relay.getTargets();
      Iterator iter=targets.iterator();
      while(iter.hasNext()) {
	log.debug("!!!!!!!!!!!! Target :"+ iter.next().toString());
      }
    }
    sensor=new TestDummySensor (sensor_name+1);
    capabilities.add( imessage.createClassification( "SecurityException", null  ) );
    capabilities.add( imessage.createClassification( "JarException", null  ) );
    reg=imessage.createRegistrationAlert(sensor,capabilities,IdmefMessageFactory.newregistration,
					 IdmefMessageFactory.SensorType);
    
    event=factory.newEvent(reg);
    
    relay = factory.newCmrRelay(event,mgrAddress);
    if(log.isDebugEnabled())
      log.debug("From testDummysensorPlugin with new Sensor  :"+ myAddress.toString() +"  relay is :"+relay.toString());
    //getBlackboardService().openTransaction();
    getBlackboardService().publishAdd(relay);
    log.debug("Publish DONE  ****************************************");
    //getBlackboardService().closeTransaction();
    //mgrAddress=new AttributeBasedAddress(dest_community,"Role",mgrrole);
   
  }
          
       
  protected void execute () {
    // process unallocated tasks
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
  
  public String getDestinationCommunity(String role) {
    if(communityService==null) {
      log.error(" Community Service is null" +myAddress.toString()); 
    }
    String destrole=null;
    if(role.equalsIgnoreCase("member")) {
      destrole="SecurityMnRManager-Enclave";
    }
    else if(role.equalsIgnoreCase("SecurityMnRManager-Enclave")) {
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
  
  
}
