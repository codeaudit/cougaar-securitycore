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
import org.cougaar.core.service.community.*;

//Security services

import  org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;


//IDMEF
import edu.jhuapl.idmef.*;

//java api;
import javax.naming.*;
import javax.naming.directory.*;
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

class QueryMappingPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof  QueryMapping ) {
      return true;
    }
    return ret;
  }
}


public class MnRQueryReceiverPlugin extends ComponentPlugin {

  // The domainService acts as a provider of domain factory services
  private DomainService domainService = null;
  private CommunityService communityService=null;
  private IncrementalSubscription capabilitiesobject;
  private IncrementalSubscription queryRelays;
  private IncrementalSubscription querymapping;
  private final int firstobject=0;
  private LoggingService loggingService;
  private MessageAddress myAddress=null;
  private Object param;
  private String mgrrole=null;
  private String myRole=null;
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
  
  public void setCommunityService(CommunityService cs) {
    //System.out.println(" set community services Servlet component :");
    this.communityService=cs;
  }
   
  
  protected void setupSubscriptions() {
    loggingService = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
    
    
    /*QueryMapping mapping=new QueryMapping();
      getBlackboardService().publishAdd(mapping);
    */
    myAddress = getBindingSite().getAgentIdentifier();
    loggingService.debug("setupSubscriptions of MnRQueryReceiverPlugin called :"+ myAddress.toString());
    String mySecurityCommunity= getMySecurityCommunity();
    loggingService.debug(" My security community :"+mySecurityCommunity +" agent name :"+myAddress.toString());  
    if(mySecurityCommunity==null) {
      loggingService.error("No Info about My  SecurityCommunity : returning Cannot continue !!!!!!"+myAddress.toString());  
      return;
    }
    else {
      myRole=getMyRole(mySecurityCommunity);
      loggingService.debug(" My Role is  :"+myRole +" agent name :"+myAddress.toString()); 
      if(!myRole.equalsIgnoreCase("SecurityMnRManager-Society")) {
	mgrrole="SecurityMnRManager-Society";
      }
    }
    /*
      System.out.println("setupSubscriptions of MnRQueryReceiverPlugin called :"+ myAddress.toString());
      Collection col=getParameters();
      if(col.size()>1) {
      loggingService.debug("setupSubscriptions of MnRQueryReceiverPlugin called  too many parameters from:"
      + myAddress.toString()); 
      }
      if(col.size()!=0){
      String params[]=new String[1];
      String parameters[]=(String[])col.toArray(new String[0]);
      mgrrole=parameters[0];
      }
    */
    capabilitiesobject= (IncrementalSubscription)getBlackboardService().subscribe
      (new CapabilitiesObjectPredicate());
    queryRelays= (IncrementalSubscription)getBlackboardService().subscribe
      (new QueryRelayPredicate());
    querymapping= (IncrementalSubscription)getBlackboardService().subscribe
       (new QueryMappingPredicate());
    
  }
  
  protected void execute () {
    MRAgentLookUp Agentlookupquery;
    CapabilitiesObject capabilities=null;
    Iterator relayiterator=null;
    boolean capabilitiesChanged=false;
    loggingService.debug("!!!!!! !!!! Execute of mnRQueryreceiver called :"+  myAddress.toString());
    if(queryRelays.hasChanged()) {
      loggingService.debug("queryRelays.hasChanged() :"+  myAddress.toString());
      Collection  capabilitiesobj_col=capabilitiesobject.getChangedCollection();
      if( capabilitiesobj_col.isEmpty()) {
	loggingService.debug(" %%% Changed collection is empty for capabilities object :@@@@@@ getting complete collection ");
	// look up query relays that require constant updates
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
      relayiterator = queryRelays.getAddedCollection().iterator();
      
    }
    if(capabilitiesobject.hasChanged()) {
      capabilitiesChanged=true;
       Collection  capabilitiesobj_col=capabilitiesobject.getChangedCollection();
      if( capabilitiesobj_col.isEmpty()) {
	loggingService.debug(" Changed collection is empty though capabilitiesobject.hasChanged returned true ");
	loggingService.debug(" returning !!!!");
	return ;
      }
      ArrayList list=new ArrayList(capabilitiesobj_col);
      if((list==null)||(list.size()==0)){
	if(loggingService.isDebugEnabled()){
	  loggingService.debug("Got capabilities object change bit the list is empty returning"
			       + myAddress.toString());
      	  return;
	}
      }
      if(list.size()>1) {
	if(loggingService.isDebugEnabled()) {
	  loggingService.debug("In capabilitiesobject.hasChanged Error Multiple capabilities object on blackboard MnRQueryReceiver Plugin agent is::"
			       + myAddress.toString());
	  loggingService.debug("CONFUSION ......  CONFUSION!!!!!!!!!!!!! Returning !!!!!!!!:");
	}
	return;
      }
      capabilities=(CapabilitiesObject)list.get(firstobject);
      relayiterator = queryRelays.getCollection().iterator();
    }
    
    updateRelayedQuery(relayiterator,capabilities,capabilitiesChanged);
  }
  
  
  
  private void updateRelayedQuery(Iterator iter,CapabilitiesObject capabilities , boolean capabilitieschanged ) {
    if((iter==null)||(capabilities==null)){
      loggingService.debug(" Both capabilities and iterator are null RETURNING !!!!!!!!!!!!!!!!:");
      return;
    }
    MRAgentLookUp Agentlookupquery=null;
    QueryMapping mapping=null;
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    loggingService.debug("updateRelayedQuery called :"+  myAddress.toString());
    CmrRelay relay;
   
    while (iter.hasNext()) {
      relay = (CmrRelay)iter.next();
      if(capabilitieschanged) {
	loggingService.debug("%%%%%%% %%%%%% %%%%%  New capabilities have come in and going to iterate through all relay and provide up date :");
	if(!relay.getSource().equals(myAddress)) {
	  loggingService.debug("****************** CAPABILITIES CHANGED  RELAY IS NOT FROM ME  ***************************");
	  loggingService.debug("cONTENTS OF RELAY ARE :"+ relay.toString());
	  if(relay.getContent() instanceof MRAgentLookUp) {
	    Agentlookupquery=(MRAgentLookUp)relay.getContent();
	    if(!Agentlookupquery.updates) {
	      loggingService.debug(" got relay without update "+Agentlookupquery.toString());
	      continue;
	    }
	    loggingService.debug(" got relay update "+Agentlookupquery.toString());
	    Collection queryMappingCollection=querymapping.getCollection();
	    mapping=findQueryMappingFromBB(relay.getUID(),queryMappingCollection) ;
	    if(mapping!=null) {
	      removeRelay(mapping);
	      mapping.setQueryList(null);
	    }
	    //}
	    //else { 
	    //if (!relay.getSource().equals(myAddress)) { 
	    // make sure it's remote, not local
	    if (loggingService.isDebugEnabled())
	      loggingService.debug(" printing receive relay which is not local:=========>"
				   +Agentlookupquery.toString());
	    //Agentlookupquery=(MRAgentLookUp)relay.getContent();
	    if (loggingService.isDebugEnabled()) {
	      loggingService.debug(" receive Query at agent :"+myAddress.toString()+ 
				   " Query is "+Agentlookupquery.toString());  
	      loggingService.debug("!!!!!!!!!!! trying to find if there are any enclave manager :");
	    }
	  }
	  else {
	    continue;
	  }
	}
      }
      if (!relay.getSource().equals(myAddress)) {
	if(relay.getContent() instanceof MRAgentLookUp) {
	  Agentlookupquery=(MRAgentLookUp)relay.getContent();
	}
      }
      if(capabilitieschanged)
	loggingService.debug(" Going to search again :------------->");
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
	  if((mapping!=null)&&(mapping.getRelayUID().equals(relay.getUID()))) {
	    mapping.setQueryList(relay_uid_list);
	    getBlackboardService().publishChange(mapping);
	  }
	  else {
	    mapping=new QueryMapping(relay.getUID(), relay_uid_list);
	    getBlackboardService().publishAdd(mapping);
	  }
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
      if (loggingService.isDebugEnabled())
	loggingService.debug("Local agents are present with the capabilities.... no of agents are :"+
			     response.size());
      Iterator response_iterator=response.iterator();
      ArrayList relay_uid_list=new ArrayList();
      while(response_iterator.hasNext()) {
	key=(String)response_iterator.next();
	//reg=(RegistrationAlert)capabilities.get(key);
	dest_address=new ClusterIdentifier(key);
	if (loggingService.isDebugEnabled())
	  loggingService.debug(" adding sensor agent to response :"+ dest_address.toString());
	relay_uid_list.add(dest_address);
      }
      if (loggingService.isDebugEnabled())
	loggingService.debug(" update response is being done :"+relay.getSource().toString() );
      relay.updateResponse(relay.getSource(),new MRAgentLookUpReply( relay_uid_list));
      getBlackboardService().publishChange(relay);
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
    Iterator removediter =queryRelays.getRemovedCollection().iterator();
    while (removediter.hasNext()) {
      relay = (CmrRelay)removediter.next();
      if (!relay.getSource().equals(myAddress)) {
	Collection queryMappingCollection=querymapping.getCollection();
	mapping=findQueryMappingFromBB(relay.getUID(),queryMappingCollection) ;
	if(mapping!=null)
	  removeRelay(mapping);
      }
    }
  }
  
  private void removeRelay(QueryMapping mapping) {
     if(mapping==null) {
       return;
     } 
     ArrayList list=mapping.getQueryList();
     if(list==null) {
       return;
     }
     if(list.isEmpty()) {
       return;
     }
     OutStandingQuery outstandingquery;
     CmrRelay relay=null;
     for(int i=0;i<list.size();i++) {
       outstandingquery=(OutStandingQuery)list.get(i);
       relay=findCmrRelay(outstandingquery.getUID());
       if((relay!=null)&&(relay.getSource().equals(myAddress))) {
	 getBlackboardService().publishRemove(relay); 
       }
     }
  }
  
  public CmrRelay  findCmrRelay (UID key) {
    CmrRelay relay=null;
    Iterator iter = queryRelays.getCollection().iterator();
    while(iter.hasNext()) {
      relay=(CmrRelay)iter.next();
      if(relay.getUID().equals(key)) {
	return relay;
      }
    }
    return null;
  } 
  private boolean isSecurityCommunity(String communityName) {
    boolean securitycommunity=false;
    if(communityService==null) {
      loggingService.debug("Community service is null "+myAddress.toString()); 
      return securitycommunity;
    }
    if(communityName==null) {
      loggingService.debug("Community name  is null "+myAddress.toString());
      return securitycommunity;
    }
    
    Attributes attributes=communityService.getCommunityAttributes(communityName);
    Attribute attribute=attributes.get("CommunityType");
    if(attribute!=null) {
      securitycommunity=attribute.contains(new String("Security"));
    }
    return securitycommunity; 
  }
    
  public List findAgent(MRAgentLookUp query, CapabilitiesObject caps, boolean sensors) {
  
    if(query==null) {
      loggingService.debug("Query was null in findAgent:"+"Sensor type :"+sensors);
      return new ArrayList();
    }
    if(caps==null) {
      loggingService.debug("Capabilities was null returning:");
      return  new ArrayList();
    }
    
    Enumeration keys=caps.keys();
    Classification queryClassification=query.classification;
    Source querySource=query.source;
    Target queryTarget=query.target;
    String community=query.community;
    String role=query.role;
    ArrayList commagents=new ArrayList();
    if((community!=null) && (role!=null)) {
      loggingService.debug(" ########## Searching with community and role combination :");
      commagents=(ArrayList)searchByCommunityAndRole(community,role);
    }
    else if((community==null)&&(role!=null))  {
      loggingService.debug(" ########## Searching with  role Only :");
      commagents=(ArrayList)searchByRole(role); 
      
    }
    else if((role==null)&&(community!=null) ) {
       loggingService.debug(" ########## Searching with  community Only :");
      commagents=(ArrayList)searchByCommunity(community); 
    }
    loggingService.debug("Printing result of community and role combination :");
    for(int i=0;i<commagents.size();i++) {
      loggingService.debug("Community and Role result at i:"+i +" agent is :"+(String)commagents.get(i));  
    }
    ArrayList classagents;
    ArrayList sourceagents;
    ArrayList targetagents;
    ArrayList commonAgents=null;
    classagents=(ArrayList)searchByClassification(queryClassification,caps,sensors);
    loggingService.debug("Printing result of query with classification  @@@@@@@@@@@@@@@@@@:" + sensors);
    for(int i=0;i<classagents.size();i++) {
      loggingService.debug("classification result at i:"+i +" agent is :"+(String)classagents.get(i));  
    }
    sourceagents=(ArrayList)searchBySource(querySource,caps,sensors);
    loggingService.debug("Printing result of query with source  @@@@@@@@@@@@@@@@@@:" + sensors);
    for(int i=0;i<sourceagents.size();i++) {
      loggingService.debug("source  result at i:"+i +" agent is :"+(String)classagents.get(i));  
    }
    targetagents=(ArrayList)searchByTarget(queryTarget,caps,sensors);
    if((queryClassification!=null) || (querySource!=null) || (queryTarget!=null)) {
      if(!classagents.isEmpty()|| !sourceagents.isEmpty()||!targetagents.isEmpty()) {
	commonAgents=(ArrayList)findCommanAgents(commagents,classagents);
	commonAgents=(ArrayList)findCommanAgents(commonAgents,sourceagents);
	commonAgents=(ArrayList)findCommanAgents(commonAgents,targetagents);	
      }
      else {
	commonAgents=new ArrayList();
      }
	
    }
    if((commonAgents==null)||(commonAgents.isEmpty()) ){
      loggingService.debug("!!!!!!!!!!!!!!!!!!!   got query result as empty :");  
    }
    else {
      loggingService.debug("Printing result of query @@@@@@@@@@@@@@@@@@:" + sensors);
	for(int i=0;i<commonAgents.size();i++) {
	  loggingService.debug("result at i:"+i +" agent is :"+(String)commonAgents.get(i));  
	}
    }
    return commonAgents;
    
  }
  
  
  public List findCommanAgents(List list1,List list2) {
    ArrayList commonList=new ArrayList();
    if(list1.isEmpty()) {
      return list2;
    }
    if(list2.isEmpty()){
      return list1;
    }
    Iterator iter=list1.iterator();
    String agentname;
    while(iter.hasNext()) {
      agentname=(String)iter.next();
      if(list2.contains(agentname)) {
	commonList.add(agentname);
      } 
    }
    return commonList;
  }
  
  private List searchByClassification(Classification searchClassification,CapabilitiesObject caps, boolean sensors) {
   
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    ArrayList agentlist=new ArrayList();
    if(searchClassification==null) {
      return agentlist;
    }
    if (loggingService.isDebugEnabled())
      loggingService.debug(" in find agent FUNCTION  query is :"+searchClassification.getName()+
			   "Origin  "+searchClassification.getOrigin() );
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled())
	loggingService.debug(" in capabilities object : Key is "+ key +" Object is :"+ reg.toString() );
      Classification [] classifications=reg.getClassifications();
      if(classifications==null) {
	return agentlist;
      }
      if(isClassificationPresent(searchClassification,classifications)) {
	loggingService.debug(" Got calssification equal:" + reg.getType());
	if(sensors) {
	  loggingService.debug(" !!!!!! Looking for sensors agents :");
	  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
	    loggingService.debug(" analyzer id is :"+ reg.getAgentName());
	    loggingService.debug(" adding sensor key :"+key);
	    agentlist.add(reg.getAgentName());
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
  
  private List searchBySource(Source searchSource,CapabilitiesObject caps, boolean sensors) {
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    Source [] sources=null;
    ArrayList agentlist=new ArrayList();
    if(searchSource==null) {
      return agentlist;
    }
    if (loggingService.isDebugEnabled())
      loggingService.debug(" in  searchBySources FUNCTION  query is :"+searchSource.toString());
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled())
	loggingService.debug(" in capabilities object : Key is "+ key +" Object is :"+ reg.toString() );
      sources=reg.getSources();
      if(sources==null) {
	 return agentlist;
      }
      if(isSourceORTargetPresent(searchSource,sources)) {
	loggingService.debug(" Got source equal:" + reg.getType());
	if(sensors) {
	  loggingService.debug(" !!!!!! Looking for sensors agents :");
	  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
	    loggingService.debug(" adding sensor key :"+key);
	    agentlist.add(reg.getAgentName());
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
  
  private List searchByTarget(Target searchTarget,CapabilitiesObject caps, boolean sensors) {
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    Target [] targets=null;
    ArrayList agentlist=new ArrayList();
    if(searchTarget==null) {
       return agentlist;
    }
    if (loggingService.isDebugEnabled())
      loggingService.debug(" in  searchByTargets FUNCTION  query is :"+searchTarget.toString());
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled())
	loggingService.debug(" in capabilities object : Key is "+ key +" Object is :"+ reg.toString() );
      targets=reg.getTargets();
      if(targets==null) {
	 return agentlist;
      }
      if(isSourceORTargetPresent(searchTarget,targets)) {
	loggingService.debug(" Got source equal:" + reg.getType());
	if(sensors) {
	  loggingService.debug(" !!!!!! Looking for sensors agents :");
	  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
	    loggingService.debug(" adding sensor key :"+key);
	    agentlist.add(reg.getAgentName());
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
  
  private List searchBySourceOfAttack() {
    
    return new ArrayList();
  }
  
  private List searchByTargetOfAttack() {
    
     return new ArrayList();
  }
  
  private String getMySecurityCommunity() {
    String mySecurityCommunity=null;
    if(communityService==null) {
      loggingService.error(" Community Service is null" +myAddress.toString()); 
    }
    String filter="(CommunityType=Security)";
    Collection securitycom=communityService.listParentCommunities(myAddress.toString(),filter);
    if(!securitycom.isEmpty()) {
      if(securitycom.size()>1) {
	loggingService.warn("Belongs to more than one Security Community " +myAddress.toString());  
	return mySecurityCommunity;
      }
      String [] securitycommunity=new String[1];
      securitycommunity=(String [])securitycom.toArray(new String[1]);
      mySecurityCommunity=securitycommunity[0];
    }
    else {
      loggingService.warn("Search  for my Security Community FAILED !!!!" +myAddress.toString()); 
    }
    
    return mySecurityCommunity;
  }
  
  private String getMyRole(String mySecurityCommunity) {
    String myRole=null;
    boolean enclavemgr=false;
    boolean societymgr=false;
    if(communityService==null) {
      loggingService.error(" Community Service is null" +myAddress.toString()); 
    }
    Collection roles =communityService.getEntityRoles(mySecurityCommunity,myAddress.toString());
    Iterator iter=roles.iterator();
    String role;
    while(iter.hasNext()) {
      role=(String)iter.next();
      if(role.equalsIgnoreCase("SecurityMnRManager-Enclave")) {
	enclavemgr=true;
      }
      else if(role.equalsIgnoreCase("SecurityMnRManager-Society")) {
	societymgr=true;
      }
    }
    if(enclavemgr) {
      myRole="SecurityMnRManager-Enclave"; 
    }
    else if(societymgr) {
      myRole="SecurityMnRManager-Society";
    }
    return myRole;
    						      
  }
  public List searchByCommunity (String community) {
    ArrayList list=new ArrayList();
    if(communityService==null) {
      loggingService.error(" Community Service is null in searchByCommunity " +myAddress.toString()); 
      return list;
    }
    if(community==null) {
       loggingService.error("Community is null in searchByCommunity " +myAddress.toString()); 
       return list;
    }
    CommunityRoster roster=communityService.getRoster(community);
    Collection agents=roster.getMemberAgents();
    Iterator agentiter=agents.iterator();
    ClusterIdentifier agent;
    while(agentiter.hasNext()) {
      agent=(ClusterIdentifier)agentiter.next();
      list.add(agent.toString());
    }
    
    return list;
  }
  public List searchByRole(String role) {
    ArrayList list=new ArrayList();
    if(communityService==null) {
      loggingService.error(" Community Service is null in searchByRole " +myAddress.toString()); 
      return list;
    }
    if(role==null) {
       loggingService.error(" Role  is null in searchByRole " +myAddress.toString()); 
       return list;
    }
    Collection communities =communityService.listAllCommunities();
    Iterator iter=communities.iterator();
    String community;
    while(iter.hasNext()) {
      community=(String)iter.next();
      Collection searchresult=communityService.searchByRole(community,role);
      Iterator roleiter=searchresult.iterator();
      while(roleiter.hasNext()) {
	list.add((String)roleiter.next());
      }	
    }
    return list; 
     
  }
  public List searchByCommunityAndRole(String community,String role) {
    ArrayList list= new ArrayList();
    if(communityService==null) {
      loggingService.error(" Community Service is null in searchByCommunityAndRole " +myAddress.toString()); 
      return list;
    }
    if(community==null) {
      loggingService.error(" community is null in searchByCommunityAndRole " +myAddress.toString()); 
      return list;
    } 
    if(role==null) {
      loggingService.error(" Role  is null in searchByCommunityAndRole " +myAddress.toString()); 
      return list;
    }
    Collection searchresult=communityService.searchByRole(community,role);
    Iterator roleiter=searchresult.iterator();
    while(roleiter.hasNext()) {
      list.add((String)roleiter.next());
    }	
    return list;
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
  
  public boolean isSourceORTargetPresent(Object inquery,Object[] inObjectArray) {
    boolean ispresent=false;
    for(int i=0;i<inObjectArray.length;i++) {
      if(areSourceORTargetEqual(inObjectArray[i],inquery)){
	ispresent=true;
	return ispresent;
      }
    }
    return ispresent ;
  }
  
  public boolean areSourceORTargetEqual(Object existing , Object inquery) {
    boolean equal=false;
    boolean nodeequal=false;
    boolean userequal=false;
    boolean serviceequal=false;
    boolean processequal=false;
    if(!(((existing instanceof Source) && (inquery instanceof Source))||
       ((existing instanceof Target) && (inquery instanceof Target)))) {
      return equal;
    }
    IDMEF_Node existingNode=null;
    IDMEF_Node queryNode=null;
    User existingUser=null;
    User queryUser=null;
    Service existingService=null;
    Service queryService=null;
    IDMEF_Process existingProcess=null;
    IDMEF_Process queryProcess=null;
    if((existing instanceof Source) && (inquery instanceof Source)) {
      Source existingSource=(Source)existing;
      Source inquerySource=(Source)inquery;
      existingNode=existingSource.getNode();
      queryNode=inquerySource.getNode();
      existingUser=existingSource.getUser();
      queryUser=inquerySource.getUser();
      existingService=existingSource.getService();
      queryService=inquerySource.getService();
      existingProcess=existingSource.getProcess();
      queryProcess=inquerySource.getProcess();
    }
    if((existing instanceof Target) && (inquery instanceof Target)) {
      Target existingTarget=(Target)existing;
      Target inqueryTarget=(Target)inquery;
      existingNode=existingTarget.getNode();
      queryNode=inqueryTarget.getNode();
      existingUser=existingTarget.getUser();
      queryUser=inqueryTarget.getUser();
      existingService=existingTarget.getService();
      queryService=inqueryTarget.getService();
      existingProcess=existingTarget.getProcess();
      queryProcess=inqueryTarget.getProcess();
      
    } 
    if((existingNode!=null)&&(queryNode!=null)){
      if(existingNode.equals(queryNode)) {
	nodeequal=true;
      }
    }
    else if((existingNode==null)&&(queryNode==null)){
      nodeequal=true;
    }
    
    if((existingUser!=null)&&(queryUser!=null)){
      if(existingUser.equals(queryUser)) {
	userequal =true;
      }
    }
    else if((existingUser==null)&&(queryUser==null)){
      userequal=true;
    }
    
    if((existingService!=null)&&(queryService!=null)){
      if(existingService.equals(queryService)) {
	serviceequal=true;
      }
    }
    else if((existingService==null)&&(queryService==null)){
      serviceequal=true;
    }
    
    if((existingProcess!=null)&&(queryProcess!=null)){
      if(existingProcess.equals(queryProcess)) {
	processequal=true;
      }
    }
    else if((existingProcess==null)&&(queryProcess==null)){
      processequal=true;
    }
    if( nodeequal &&  userequal &&  serviceequal &&  processequal) {
      equal=true;
    }
    return equal;
     
  }
  
  public QueryMapping findQueryMappingFromBB(UID givenUID, Collection queryMappingCol ) {
    QueryMapping foundqMapping=null;
    ArrayList relayList;
    OutStandingQuery outstandingq;  
    //QueryMapping tempqMapping;
    if(!queryMappingCol.isEmpty()){
      if (loggingService.isDebugEnabled())
	loggingService.debug("Going to find uid from list of Query mapping Objects on bb"+queryMappingCol.size()); 
      Iterator iter=queryMappingCol.iterator();
      while(iter.hasNext()) {
	foundqMapping=(QueryMapping)iter.next();
	relayList=foundqMapping.getQueryList();
	for(int i=0;i<relayList.size();i++) {
	  outstandingq=(OutStandingQuery)relayList.get(i);
	  if(outstandingq.getUID().equals(givenUID)) {
	    if (loggingService.isDebugEnabled())
	      loggingService.debug(" Found given uid :"+ givenUID +" in object with UID :"+outstandingq.getUID());
	    return foundqMapping;
	  }
	}
      }
      
    }
    else {
      return null;
    }
    return null;
  }
  
   
}
