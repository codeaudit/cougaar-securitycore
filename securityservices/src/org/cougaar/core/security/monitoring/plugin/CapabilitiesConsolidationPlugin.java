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


import java.util.Enumeration;
import java.util.Collection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Vector;
import java.util.Iterator;

import edu.jhuapl.idmef.*;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.core.service.*;
import org.cougaar.core.mts.*;
import org.cougaar.core.agent.*;
import org.cougaar.core.domain.RootFactory;
import org.cougaar.core.domain.Factory;
import org.cougaar.core.mts.MessageAddress;

// Cougaar security services
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.CmrObject;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CapabilitiesObject;
import org.cougaar.core.security.monitoring.idmef.*;
import org.cougaar.core.security.monitoring.blackboard.*;

class ModifiedCapabilitiesPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CapabilitiesObject ) {
      return true;
    }
    return ret;
  }
}

class ConsolidatedCapabilitiesRelayPredicate implements UnaryPredicate{
 public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      Event event = (Event)relay.getContent();
      ret = (event.getEvent() instanceof ConsolidatedCapabilities);
    }
    return ret;
  }
}

//  This code is not required any more 
class AgentRegistrationPredicate implements UnaryPredicate{
 public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof Event ) {
      Event e=(Event)o;
      IDMEF_Message msg=e.getEvent();
      if(msg instanceof AgentRegistration){
	return true;
      }
    }
    return ret;
  }
}


/**
 *
 **/
public class CapabilitiesConsolidationPlugin extends ComponentPlugin {

  // The domainService acts as a provider of domain factory services
  private DomainService domainService = null;

  private IncrementalSubscription modifiedcapabilities;
  private IncrementalSubscription capabilitiesRelays;
  private IncrementalSubscription agentRegistrations;
  private LoggingService log;

  private int firstobject=0;
  private AttributeBasedAddress mgrAddress;
  private MessageAddress myAddress;
  
  private String dest_community;
  private Object param;  
  private String mgrrole=null;
  /** Holds value of property loggingService. */
  private LoggingService loggingService;  
  
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
     
  
  /**
   * subscribe to tasks and programming assets
   */
  protected void setupSubscriptions() {
    log = (LoggingService)
      getBindingSite().getServiceBroker().getService(this,
	LoggingService.class, null);

    myAddress = getBindingSite().getAgentIdentifier();
    if (log.isDebugEnabled()) {
      log.debug("setupSubscriptions of CapabilitiesConsolidationPlug in called for "
		+ myAddress.toAddress()); 
    }
     Collection col=getParameters();
    if(col.size()>2) {
       log.debug("setupSubscriptions of CapabilitiesProcessingPlugin called  too many parameters :"); 
    }
    if(col.size()!=0){
      String parameters[]=(String[])col.toArray(new String[0]);
      mgrrole=parameters[0];
      if(col.size()>1) {
	dest_community=parameters[1];
      }
    }
    
    
    // System.out.println(" got Role as  in ccp%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"+role);
    //
    // This needs to be converted to make mgrAddress an AttributeBasedAddress.
    // For now, just send by name.
    //
    /*
    String mgrName = "MRManager";
    Iterator params = getParameters().iterator();
    while (params.hasNext()) {
        String param = (String)params.next();
        mgrName = param;
    }
    */
    if(dest_community!=null)
      mgrAddress=new AttributeBasedAddress(dest_community,"SecurityMnRManager",mgrrole);
     //mgrAddress = new ClusterIdentifier(mgrrole);

    modifiedcapabilities= (IncrementalSubscription)getBlackboardService().subscribe(new ModifiedCapabilitiesPredicate());
    capabilitiesRelays= (IncrementalSubscription)getBlackboardService().subscribe(new ConsolidatedCapabilitiesRelayPredicate());
    agentRegistrations= (IncrementalSubscription)getBlackboardService().subscribe(new AgentRegistrationPredicate());
  }


  /**
   * Top level plugin execute loop.  
   */
  protected void execute () {
    // Unwrap subordinate capabilities from new/changed/deleted relays
    updateRelayedCapabilities();
    
    log.debug(" Execute of CapabilitiesConsolidation Plugin called !!!!!!!!");
     DomainService service=getDomainService();
    if(service==null) {
      log.debug(" Got service as null in Test Dummy Sensor  :");
      return;
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    //Event event=null;
    Collection  modifiedcapabilities_col=modifiedcapabilities.getChangedCollection();
    ArrayList list=new ArrayList(modifiedcapabilities_col);
    
    if((list==null)||(list.size()==0)){
      log.debug(" !!!! No modified capabilities currently present  !!!!!!! RETURNING  !!!!!!!!!!!!!!!!");
      return;
    }
    
    if(list.size()>1) {
      log.debug(" Error Multiple complete capabilities object on blackboard in Capabilities Consolidation plugin !!!!!!!!!!!!!!!!!!! CONFUSION CONFUSION CONFUSION  RETURNIG !!!!!!!:");
      return;
    }
   
    ConsolidatedCapabilities myconsolidation=null;
    if(mgrrole==null) {
      Event ev=findEventFrom(myAddress);
      if(ev!=null) {
	myconsolidation=(ConsolidatedCapabilities)ev.getEvent();
	System.out.println(" top consolidation is &&&&&&&&&&&&&&&&&&&&&&&&&:"+myconsolidation.toString());
      }
      else {
	System.out.println(" top consolidation is &&&&&&&&&&&&&&&&&&&&&&&&&:  NULL NULL ");
      }
    }

    ConsolidatedCapabilities consCapabilities=null;
    CapabilitiesObject capabilitiesobject=null;
    capabilitiesobject=(CapabilitiesObject )list.get(firstobject);
    consCapabilities=createConsolidatedCapabilities();
    RegistrationAlert registration=null;
    Classification consclassifications[]=consCapabilities.getClassifications();
    Classification regclassifications[]=null;
    Enumeration keys=capabilitiesobject.keys();
    String key=null;
    if(mgrrole!=null) {
      while(keys.hasMoreElements()) {
	key=(String)keys.nextElement();
	log.debug(" KEY IN CAPABILITIES OBJECT IS :"+key);
	registration=(RegistrationAlert)capabilitiesobject.get(key);
	regclassifications=registration.getClassifications();
	if(consclassifications==null){
	  //log.debug("consclassifications was null Creating one :"); 
	  consclassifications=new Classification[regclassifications.length];
	  System.arraycopy(regclassifications,0,consclassifications,0,regclassifications.length);
	  printConsolidation(consclassifications," First one added after creating cons obj:");
	}
	else {
	  log.debug("consclassifications was NOT NULL Consolidating !!!!!!!!!! :"); 
	  printConsolidation(consclassifications," Already cons obj present before adding new %%%%%%%%%%%%%%%% :");
	  consclassifications=getConsolidatedClassification(regclassifications,consclassifications);
	  printConsolidation(consclassifications," Already cons obj present added new $$$$$$$$$$$$$$$$$$ :");
	}
	    
      }
      consCapabilities.setClassifications(consclassifications);
      Analyzer analyzer=new Analyzer();
      analyzer.setAnalyzerid(myAddress.toString());
      consCapabilities.setAnalyzer(analyzer);
      log.debug("@@@@@@@@@@@@@@@@@@@@@@@@@   **********************  consolidated classification is @@@@@@@@@@@@@@@@@@@@@@@@@:");
      consclassifications=consCapabilities.getClassifications();
      printConsolidation(consclassifications," consolidated classification after processing is :");
      System.out.println("======================================>Relay to be created will be  :"+ consCapabilities.toString()); 
      log.debug("======================================>Relay to be created will be  :"+ consCapabilities.toString());
      /*  if(role.equals(IdmefMessageFactory.SocietyMgrType)) {
	  getBlackboardService().publishAdd(factory.newEvent(consCapabilities));
	  }
	  else {
      */
      addOrUpdateRelay(factory.newEvent(consCapabilities), factory);
    }
    
    // }
  }


  public ConsolidatedCapabilities createConsolidatedCapabilities() {
    DomainService service=getDomainService();
    if(service==null) {
      log.debug(" Got service as null in CapabilitiesConsolidationPlugin :");
      return null;
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    ConsolidatedCapabilities conscapabilities=imessage.createConsolidatedCapabilities();
    if(mgrrole==null)
      conscapabilities.setType(IdmefMessageFactory.SocietyMgrType);
    else 
      conscapabilities.setType(IdmefMessageFactory.EnclaveMgrType);
    return conscapabilities;
  }

    
  public void printConsolidation(Classification[] classifications, String msg) {
    log.debug(msg);
    Classification classification=null;
    for(int i=0;i<classifications.length;i++){
      classification= classifications[i];
      converttoString( classification);
    }
  }

   
  public Classification[] getConsolidatedClassification( Classification[] newcapabilities ,Classification[] existingcapabilities ) {

    //Arrays.sort((Object[])existingcapabilities);
    printConsolidation(newcapabilities,"New Capabilities:");
    printConsolidation(existingcapabilities,"Existing  Capabilities:");
    Vector indexes=new Vector();
    Classification existingclas=null;
    Classification newclas=null;
    int index=-1;
    boolean found=false;
    for(int i=0;i<newcapabilities.length;i++){
      found=false;
      newclas=newcapabilities[i];
      for(int j=0;j<existingcapabilities.length;j++) {
	existingclas=existingcapabilities[j];
	if(!areClassificationsEqual(existingclas,newclas)) {
	  continue;
	}
		
	found=true;
	break;
		
      }
      if(!found) {
	log.debug(" new  capabilities :");
	converttoString(newclas);
	indexes.add(newclas);
      }
	   
    }
    Classification[] consolidate=new Classification[existingcapabilities.length+indexes.size()];
    Classification clas=null;
    System.arraycopy(existingcapabilities,0,consolidate,0,existingcapabilities.length);
    index=existingcapabilities.length;
    for(int i=0;i<indexes.size();i++){
      clas = (Classification) indexes.elementAt(i);
      consolidate[i+index]=clas;
      // log.debug("New Classifications are :"+clas.toString());
    }
    return consolidate;
  }

  public boolean areClassificationsEqual(Classification existingclassification,Classification newclassification) {
    boolean equal=false;
    if((existingclassification.getOrigin().trim().equals(newclassification.getOrigin().trim()))&&(existingclassification.getName().trim().equals(newclassification.getName().trim()))) {
      return true;
    }
    return equal;
	
  }
    
  public void converttoString(Classification classification) {
    log.debug(" Classification origin :"+classification.getOrigin());
    log.debug(" Classification Name :"+classification.getName());
    log.debug(" Classification URL :"+classification.getUrl());
  }
  
  private void addOrUpdateRelay(Event event, CmrFactory factory) {
      if (loggingService.isDebugEnabled())
          loggingService.debug("addOrUpdateRelay");
      CmrRelay relay = null;
      // Find the (one) outgoing relay
      Iterator iter = capabilitiesRelays.iterator();
      while (iter.hasNext()) {
        CmrRelay aRelay = (CmrRelay)iter.next();
        if (aRelay.getSource().equals(myAddress)) {
            relay = aRelay;
            break;
        }
      }
      if (relay == null) {
	 if (loggingService.isDebugEnabled())
          loggingService.debug(" No relay was present creating one for Event "+ event.toString());
          relay = factory.newCmrRelay(event, mgrAddress);
          getBlackboardService().publishAdd(relay);
      } else {
          relay.updateContent(event, null);
          getBlackboardService().publishChange(relay);
      }
  }
  
   private void updateRelayedCapabilities() {
       if (capabilitiesRelays.hasChanged()) {
	  if (loggingService.isDebugEnabled())
	    loggingService.debug("capabilitiesRelays has changed ");
           CmrRelay relay;
           // New relays
           Iterator iter = capabilitiesRelays.getAddedCollection().iterator();
           while (iter.hasNext()) {
               relay = (CmrRelay)iter.next();
               if (!relay.getSource().equals(myAddress)) { // make sure it's remote, not local
		 System.out.println(" printing receive relay which is not my address:=========================>"+relay.getContent().toString());
                   getBlackboardService().publishAdd(relay.getContent());
               }
           }
           
           // Changed relays
           iter = capabilitiesRelays.getChangedCollection().iterator();
           while (iter.hasNext()) {
               relay = (CmrRelay)iter.next();
               if (!relay.getSource().equals(myAddress)) {
                   Event oldCapabilities = findEventFrom(relay.getSource());
                   if (oldCapabilities != null)
                       getBlackboardService().publishRemove(oldCapabilities);
                   getBlackboardService().publishAdd(relay.getContent());
               }
           }
           // Removed relays
           iter = capabilitiesRelays.getRemovedCollection().iterator();
           while (iter.hasNext()) {
               relay = (CmrRelay)iter.next();
               if (!relay.getSource().equals(myAddress)) {
                   Event oldCapabilities = findEventFrom(relay.getSource());
                   if (oldCapabilities != null)
                       getBlackboardService().publishRemove(oldCapabilities);
               }
           }
       }
   }
   
   /**
    * Find the previous AgentRegistration Event from this source (if any)
    */
   private Event findEventFrom(MessageAddress source) {
       Iterator iter = this.agentRegistrations.iterator();
       while (iter.hasNext()) {
           Event event = (Event)iter.next();
           if (event.getSource().equals(source))
               return event;
       }
       return null;
   }
  
  public void printConsolidationHash() {
    
    
  }
  /** Getter for property loggingService.
   * @return Value of property loggingService.
   */
  public LoggingService getLoggingService() {
      return loggingService;
  }
  
  /** Setter for property loggingService.
   * @param loggingService New value of property loggingService.
   */
  public void setLoggingService(LoggingService loggingService) {
      this.loggingService = loggingService;
  }
  
}

