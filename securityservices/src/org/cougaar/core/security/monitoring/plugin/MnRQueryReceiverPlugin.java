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
//import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.*;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.multicast.AttributeBasedAddress;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.core.util.UID;

//Security services

import  org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;



//IDMEF
import edu.jhuapl.idmef.*;

//java api;

import java.util.Enumeration;
import java.util.Collection;
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;


class CapabilitiesObjectPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CapabilitiesObject ) {
      return true;
    }
    return ret;
  }
}

class QueryRelayPredicate implements  UnaryPredicate{
 
   public boolean execute(Object o) {
      boolean ret = false;
     if (o instanceof CmrRelay ) {
       CmrRelay relay = (CmrRelay)o;
       ret = ( relay.getContent() instanceof MRAgentLookUp );
     }
     return ret;
   }
}

/*
class QueryMappingPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof  QueryMapping ) {
      return true;
    }
    return ret;
  }
}
*/

public class MnRQueryReceiverPlugin extends ComponentPlugin {

 // The domainService acts as a provider of domain factory services
  private DomainService domainService = null;
  private IncrementalSubscription capabilitiesobject;
  private IncrementalSubscription queryRelays;
  //private IncrementalSubscription querymapping;
  private final int firstobject=0;
  private LoggingService loggingService;
  private MessageAddress myAddress=null;
  private Object param;
  private String mgrrole=null;
  // private ClusterIdentifier destAddress;

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
    loggingService = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
    
    
    /*QueryMapping mapping=new QueryMapping();
    getBlackboardService().publishAdd(mapping);
    */
    myAddress = getBindingSite().getAgentIdentifier();
    loggingService.debug("setupSubscriptions of MnRQueryReceiverPlugin called :"+ myAddress.toString());
    //System.out.println("setupSubscriptions of MnRQueryReceiverPlugin called :"+ myAddress.toString());
    Collection col=getParameters();
    if(col.size()>1) {
      loggingService.debug("setupSubscriptions of MnRQueryReceiverPlugin called  too many parameters from:"
			   + myAddress.toString()); 
      /*
      System.out.println("setupSubscriptions of MnRQueryReceiverPlugin called  too many parameters from:"
			   + myAddress.toString()); 
      */
    }
    if(col.size()!=0){
      String params[]=new String[1];
      String parameters[]=(String[])col.toArray(new String[0]);
      mgrrole=parameters[0];
      
    }
    capabilitiesobject= (IncrementalSubscription)getBlackboardService().subscribe
      (new CapabilitiesObjectPredicate());
    queryRelays= (IncrementalSubscription)getBlackboardService().subscribe
      (new QueryRelayPredicate());
    /* querymapping= (IncrementalSubscription)getBlackboardService().subscribe
      (new QueryMappingPredicate());
    */
  }
  
  protected void execute () {
     updateRelayedQuery();
  }
  
  private void updateRelayedQuery() {
    MRAgentLookUp Agentlookupquery;
    CapabilitiesObject capabilities;
    QueryMapping mapping;
     CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
     loggingService.debug("updateRelayedQuery called :"+  myAddress.toString());
    if (queryRelays.hasChanged()) {
      loggingService.debug("queryRelays.hasChanged() :"+  myAddress.toString());
      Collection  capabilitiesobj_col=capabilitiesobject.getChangedCollection();
      if( capabilitiesobj_col.isEmpty()) {
	 loggingService.debug(" Changed collection is empty for capabilities object :@@@@@@ getting complete collection ");
	 capabilitiesobj_col=capabilitiesobject.getCollection();
      }
      ArrayList list=new ArrayList(capabilitiesobj_col);
      if((list==null)||(list.size()==0)){
	if(loggingService.isDebugEnabled()){
	  loggingService.debug("No capabilities object present in MnRQuery Receiver: RETURNING !!!!!!!!!!!"
			       + myAddress.toString());
	  return;
	}
      }
      if(list.size()>1) {
	if(loggingService.isDebugEnabled()) {
	  loggingService.debug(" Error Multiple capabilities  object on blackboard MnRQueryReceiver Plugin in agent::"
			     + myAddress.toString());
	  loggingService.debug("CONFUSION ......  CONFUSION!!!!!!!!!!!!! Exiting !!!!!!!!:");
	}
	return;
	
      }
      capabilities=(CapabilitiesObject)list.get(firstobject);
      if (loggingService.isDebugEnabled())
	loggingService.debug("Query Relays has changed in MnRQuery Plugin at address   "+ myAddress.toString());
      CmrRelay relay;
      // New relays
      Iterator iter = queryRelays.getAddedCollection().iterator();
      while (iter.hasNext()) {
	relay = (CmrRelay)iter.next();
	if (!relay.getSource().equals(myAddress)) { 
          // make sure it's remote, not local
	  if (loggingService.isDebugEnabled())
	  loggingService.debug(" printing receive relay which is not local:=========>"
			     +relay.getContent().toString());
	  Agentlookupquery=(MRAgentLookUp)relay.getContent();
	  if (loggingService.isDebugEnabled()) {
	    loggingService.debug(" receive Query at agent :"+myAddress.toString() +Agentlookupquery.toString());  
	    loggingService.debug("!!!!!!!!!!! trying to find if there are any enclave manager :");
	  }
	  List response= findAgent(Agentlookupquery,capabilities,false);
	  if (loggingService.isDebugEnabled())
	    loggingService.debug(" found response for enclave manager and size of response :"+response.size() ); 
	  if(!response.isEmpty()) {
	    if (loggingService.isDebugEnabled())
	      loggingService.debug("MnRQueryReceiver plugin  Creating new relays :"+ myAddress.toString());
	    Iterator response_iterator=response.iterator();
	    String key=null;
	    RegistrationAlert reg;
	    ClusterIdentifier dest_address;
	    ArrayList relay_uid_list=new ArrayList();
	    boolean modified=false;
	    if (loggingService.isDebugEnabled())
	      loggingService.debug(" going through list of agents found in Query receiver plugin  :");
	    while(response_iterator.hasNext()) {
	      key=(String)response_iterator.next();
	      reg=(RegistrationAlert)capabilities.get(key);
	      dest_address=new ClusterIdentifier(key);
	      if (loggingService.isDebugEnabled())
		loggingService.debug(" destination address for relay is :"+dest_address.toString());
	      CmrRelay forwardedrelay = null;
	      forwardedrelay = factory.newCmrRelay(Agentlookupquery, dest_address);
	      relay_uid_list.add(new OutStandingQuery(forwardedrelay.getUID()));
	      getBlackboardService().publishAdd(forwardedrelay);
	      modified=true;
	    }
	    if(modified) {
	      if (loggingService.isDebugEnabled())
		loggingService.debug(" creating new Mapping query Object:");
	      mapping=new QueryMapping(relay.getUID(), relay_uid_list);
	      getBlackboardService().publishAdd(mapping);
	    }
	  }
	  if (loggingService.isDebugEnabled())
	    loggingService.debug(" Finished query for subordinate managers.going to look for local sensor Agents :"); 
	  String key=null;
	  RegistrationAlert reg;
	  ClusterIdentifier dest_address;
	  response= findAgent(Agentlookupquery,capabilities,true);
	  if(response.isEmpty()) {
	    if (loggingService.isDebugEnabled())
	      loggingService.debug("No Local agents are present with the capabilities....  returning :");
	    return;
	  }
	  else {
	    if (loggingService.isDebugEnabled())
	       loggingService.debug("Local agents are present with the capabilities.... no of agents are :"+
				    response.size());
	  }
	  Iterator response_iterator=response.iterator();
	  ArrayList relay_uid_list=new ArrayList();
	  while(response_iterator.hasNext()) {
	    key=(String)response_iterator.next();
	    reg=(RegistrationAlert)capabilities.get(key);
	    dest_address=new ClusterIdentifier(reg.getAgentName());
	    if (loggingService.isDebugEnabled())
	      loggingService.debug(" adding sensor agent to response :"+ dest_address.toString());
	    relay_uid_list.add( dest_address);
	  }
	  if (loggingService.isDebugEnabled())
	    loggingService.debug(" update response is being done :"+relay.getSource().toString() );
	  relay.updateResponse(relay.getSource(),new MRAgentLookUpReply( relay_uid_list));
	  getBlackboardService().publishChange(relay);
	}
      }
      
      // Changed relays
      /*
	Currently not handling any relay change for relays that are not locally created    
      System.out.println("Changed relays of receiver plugin going to be executed:");
      Collection qcol= queryRelays.getChangedCollection();
      System.out.println(" coll size in reci plugin is :"+qcol.size());
     
      iter = queryRelays.getChangedCollection().iterator();
      while (iter.hasNext()) {
	relay = (CmrRelay)iter.next();
	if (!relay.getSource().equals(myAddress)) {
	  
	  Event oldCapabilities = findEventFrom(relay.getSource());
	  if (oldCapabilities != null)
	    getBlackboardService().publishRemove(oldCapabilities);
	  loggingService.debug(" printing replaced  relay which is not local:=========>"
			       +relay.getContent().toString());
	  getBlackboardService().publishAdd(relay.getContent());
	  }

	 
      }
      */
      // Removed relays
      iter =queryRelays.getRemovedCollection().iterator();
      while (iter.hasNext()) {
	relay = (CmrRelay)iter.next();
	if (!relay.getSource().equals(myAddress)) {/*
	  Event oldCapabilities = findEventFrom(relay.getSource());
	  if (oldCapabilities != null)
	  getBlackboardService().publishRemove(oldCapabilities);
						   */
	}
      }
    }
  }
    
  public List findAgent(MRAgentLookUp query, CapabilitiesObject caps, boolean sensors) {

    Enumeration keys=caps.keys();
    Classification queryClassification=query.classification;
    String key=null;
    RegistrationAlert reg;
    ArrayList agentlist=new ArrayList();
    if (loggingService.isDebugEnabled())
      loggingService.debug(" in find agent FUNCTION  query is :"+queryClassification.getName()+
			    "Origin  "+queryClassification.getOrigin() );
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled())
	loggingService.debug(" in capabilities object : Key is "+ key +" Object is :"+ reg.toString() );
      Classification [] classifications=reg.getClassifications();
      if(isClassificationPresent(queryClassification,classifications)) {
	 loggingService.debug(" Got calssification equal:" + reg.getType());
	if(sensors) {
	   loggingService.debug(" !!!!!! Looking for agents sensors :");
	  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
	     loggingService.debug(" adding sensor key :"+key);
	    agentlist.add(key);
	  }
	}
	else {
	   loggingService.debug(" !!!!! looking for Security  manager :");
	  if((reg.getType().equals( IdmefMessageFactory.EnclaveMgrType))||
	     (reg.getType().equals( IdmefMessageFactory.SocietyMgrType))) {
	    loggingService.debug(" adding security manager  key :"+key);
	    agentlist.add(key);
	  }
	}
      }
    }
    return agentlist;
    
  } 
  
  public boolean areClassificationsEqual(Classification existingclassification,Classification newclassification) {
    boolean equal=false;
    if((existingclassification.getOrigin().trim().equals(newclassification.getOrigin().trim()))
       &&(existingclassification.getName().trim().equals(newclassification.getName().trim()))) {
      // loggingService.debug(" returning true  :");
      return true;
    }   
    return equal;
  }
  
  public boolean isClassificationPresent(Classification queryclassification,Classification[] classificationList) {
    Classification currentclassification;
    boolean isclassification=false;
    for(int i=0;i<classificationList.length;i++) {
      currentclassification=classificationList[i];
      if(areClassificationsEqual(queryclassification,currentclassification)){
	isclassification=true;
	return isclassification;
      }
    }
    return isclassification  ;
  }
  
   
}
