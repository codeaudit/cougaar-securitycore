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
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("setupSubscriptions of MnRQueryReceiverPlugin called :"
			   + myAddress.toString());
    }
    String mySecurityCommunity= getMySecurityCommunity();
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("My security community :"+mySecurityCommunity
			   +" agent name :"+myAddress.toString());  
    }
    if(mySecurityCommunity==null) {
      loggingService.error("No Info about My SecurityCommunity"+myAddress.toString());  
      return;
    }
    else {
      myRole=getMyRole(mySecurityCommunity);
      if (loggingService.isDebugEnabled()) {
	loggingService.debug("My Role is:" + myRole + ". Agent name:"+myAddress.toString()); 
      }
      if(!myRole.equalsIgnoreCase("SecurityMnRManager-Society")) {
	mgrrole="SecurityMnRManager-Society";
      }
    }
    
    capabilitiesobject= (IncrementalSubscription)getBlackboardService().subscribe
      (new CapabilitiesObjectPredicate());
    queryRelays= (IncrementalSubscription)getBlackboardService().subscribe
      (new QueryRelayPredicate());
    querymapping= (IncrementalSubscription)getBlackboardService().subscribe
      (new QueryMappingPredicate());
    
  }
  
  protected void execute () {
    MRAgentLookUp agentlookupquery;
    // The list of this M&R manager agent capabilities.
    CapabilitiesObject capabilities=null;
    // An iterator through a list of MRAgentLookUp.
    Iterator relayiterator=null;
    boolean capabilitiesChanged=false;
    if ((capabilitiesobject == null) || (queryRelays == null)
	|| (querymapping == null)) {
      return;
    }
    loggingService.debug("Execute of mnRQueryreceiver called :"
			 + myAddress.toString());
    if((capabilitiesobject.hasChanged()) && (queryRelays.hasChanged())) {
      loggingService.debug("Capabilities & Query both have changed :");
      Collection  capabilitiesobj_col=capabilitiesobject.getChangedCollection();
      if( capabilitiesobj_col.isEmpty()) {
	loggingService.debug("Changed collection is empty though capabilitiesobject.hasChanged in execute  returned true ");
	loggingService.debug("Changed collection is empty going to get the complete collection ");
	capabilitiesobj_col=capabilitiesobject.getCollection();
	capabilitiesChanged=false;
       
      }
      else {
	capabilitiesChanged=true;
      }
      ArrayList list=new ArrayList(capabilitiesobj_col);
      if((list==null)||(list.size()==0)) {
	if(loggingService.isDebugEnabled()) {
	  loggingService.debug("Got capabilities object change but the list is empty returning"
			       + myAddress.toString());
	}
	return;
      }
      if(list.size()>1) {
	if(loggingService.isErrorEnabled()) {
	  loggingService.error("Multiple capabilities object on blackboard. Agent is:"
			       + myAddress.toString());
	}
	return;
      }
      // capabilities may be null if no sensor has registered yet.
      capabilities=(CapabilitiesObject)list.get(firstobject);
      if(capabilitiesChanged) {
	loggingService.debug(" Capabilities have changed getting the complete Query collection:");
	relayiterator = queryRelays.getCollection().iterator();
      }
      else {
	Collection coll= queryRelays.getAddedCollection();
	if(coll.isEmpty()) {
	  loggingService.debug(" Capabilities & Query  has changed but the changed collection returns empty :returning:");
	  return;
	}
	relayiterator = coll.iterator();
	loggingService.debug("Number of new MnRLookupQuery:" +coll.size()); 
       
      }
    } 
    else if(capabilitiesobject.hasChanged()) {
      // New capability registration objects have been received
      loggingService.debug(" Capabilities has changed :");
      Collection  capabilitiesobj_col=capabilitiesobject.getChangedCollection();
      if( capabilitiesobj_col.isEmpty()) {
	loggingService.info("Changed collection is empty though capabilitiesobject.hasChanged returned true ");
	return ;
      }
      ArrayList list=new ArrayList(capabilitiesobj_col);
      if((list==null)||(list.size()==0)){ 
	if(loggingService.isDebugEnabled()){
	  loggingService.debug("Got capabilities object change but the list is empty returning"
			       + myAddress.toString());
	}
	return;
      }
      if(list.size()>1) {
	if(loggingService.isErrorEnabled()) {
	  loggingService.error("Multiple capabilities object on blackboard. Agent is:"
			       + myAddress.toString());
	}
	return;
      }
      capabilitiesChanged=true;
      loggingService.debug("Capabilities object has changed so getting all query relays");
      // capabilities may be null if no sensor has registered yet.
      capabilities=(CapabilitiesObject)list.get(firstobject);
      relayiterator = queryRelays.getCollection().iterator();
    }
    else if(queryRelays.hasChanged()) {
      // New MnRLookup queries have been received
      loggingService.debug("At least one MnRLookupQuery has changed. My agent is"
			   +  myAddress.toString());
      Collection  capabilitiesobj_col=capabilitiesobject.getCollection();
      ArrayList list=new ArrayList(capabilitiesobj_col);
      if((list==null)||(list.size()==0)){
	if(loggingService.isDebugEnabled()) {
	  loggingService.debug("No capabilities object present in MnRQuery Receiver"
			       + myAddress.toString());
	}
	return;
      }
      if(list.size()>1) {
	if(loggingService.isErrorEnabled()) {
	  loggingService.error("Multiple capabilities object on blackboard MnRQueryReceiver Plugin in agent:" + myAddress.toString());
	}
	return;
      }
      capabilities=(CapabilitiesObject)list.get(firstobject);
      Collection coll= queryRelays.getAddedCollection();
      relayiterator = coll.iterator();
      loggingService.debug("Number of new MnRLookupQuery:" +coll.size()); 
      
    }
    updateRelayedQuery(relayiterator,capabilities,capabilitiesChanged);
  }
  
  
  /**
   * Process MnRLookupQuery queries.
   * @param iter - An iterator through the list of MRAgentLookUp collection
   * @param capabilities - The capabilites of this M&R manager agent
   *                       and its subordinates.
   * @param capabilitieschanged - true if the capabilities have changed.
   */
  private void updateRelayedQuery(Iterator iter,CapabilitiesObject capabilities,
				  boolean capabilitieschanged ) {
    if((iter==null)||(capabilities==null)) {
      loggingService.debug("Either capabilities or iterator is null");
      return;
    }
    MRAgentLookUp agentlookupquery=null;
    QueryMapping mapping=null;
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    loggingService.debug("updateRelayedQuery called :"+  myAddress.toString());
    printhash(capabilities);
    if(capabilitieschanged) {
      loggingService.debug("Execute is called with new Capabilities");
    }
    else {
      loggingService.debug("Execute is called with new Query");
    }
    
    CmrRelay relay;
    boolean newquery=false;
    boolean modified=false;
    while (iter.hasNext()) {
      newquery=false;
      mapping=null;
      modified=false;
      relay = (CmrRelay)iter.next();
      Collection queryMappingCollection=querymapping.getCollection();
      if(relay.getContent() instanceof MRAgentLookUp) {
	agentlookupquery=(MRAgentLookUp)relay.getContent();
	if(agentlookupquery==null) {
	  loggingService.warn("Contents of the relay is null:"+relay.toString());
	  continue;
	}
	if(!agentlookupquery.updates) {
	  loggingService.debug("Got relay without update "
			       +agentlookupquery.toString());
	  continue;
	}
	if (loggingService.isDebugEnabled()) {
	  loggingService.debug("Receive Query at agent:"+myAddress.toString()+ 
			       " Query is "+agentlookupquery.toString());  
	}
	boolean isqueryoriginator= isRelayQueryOriginator(relay.getUID(),queryMappingCollection);
	boolean issubquery=isRelaySubQuery(relay.getUID(),queryMappingCollection);
	if(capabilitieschanged) {
	  loggingService.debug("New capabilities have come in and going to iterate through all relay and provide up date :");
	  if(isqueryoriginator){
	    loggingService.debug("Current relay is the originator of query:"+ relay.toString());
	    mapping=findQueryMappingFromBB(relay.getUID(),queryMappingCollection) ;
	    if(mapping!=null) {
	      loggingService.debug("Removing if any mappingand relay objects  :");
	      removeRelay(mapping);
	      mapping.setQueryList(null);
	      mapping.setResultPublished(false);
	      modified=true;
	    }
	    else {
	      loggingService.debug("Query Originator wa true but mapping object is null :");
	    }
	  }
	  else if(issubquery) {
	    loggingService.debug("Relay query is a sub query going to continue with next query relay:");
	    continue;
	  }
	  else {
	    /*Received a new query relay 
	     */
	    loggingService.debug("Relay query is a new  query :"); 
	    newquery=true;
	  }
	}
	else {
	  if(isqueryoriginator) {
	    loggingService.debug(" ERROR !!!!!!!!!!!!!! some how reading the comple query relay ");
	  }
	  loggingService.debug("Not change capabilities but could be new original query /subquery:");
	  if(issubquery) {
	    loggingService.debug("Relay query is a sub query going to continue with next query relay:");
	    continue;
	  }
	  else {
	    loggingService.debug("Relay query is a new  query :" + relay.toString()); 
	    newquery=true;
	  }
	}
      }
      else {
	/*
	  Not an instance or MRAgentLookUp contine with te next relay.  */
	loggingService.debug("Current relay is not instance of MnRAgentLookup:"
			     + relay.toString());
	continue;
      }
      if(capabilitieschanged) {
	loggingService.debug("Going to search again For persisted query ");
      }
      
      List response= findAgent(agentlookupquery, capabilities, false);
      if (loggingService.isDebugEnabled()) {
	loggingService.debug("Found response for enclave manager and size of response :"
			     +response.size() );
      }
      if(!response.isEmpty()) {
	if (loggingService.isDebugEnabled()) {
	  loggingService.debug("MnRQueryReceiver plugin  Creating new relays:"
			       + myAddress.toString());
	}
	Iterator response_iterator=response.iterator();
	String key=null;
	RegistrationAlert reg;
	ClusterIdentifier dest_address;
	ArrayList relay_uid_list=new ArrayList();
	//boolean modified=false;
	if (loggingService.isDebugEnabled()) {
	  loggingService.debug("Going through list of agents found in Query receiver plugin  :");
	}
	while(response_iterator.hasNext()) {
	  key=(String)response_iterator.next();
	  reg=(RegistrationAlert)capabilities.get(key);
	  dest_address=new ClusterIdentifier(key);
	  if (loggingService.isDebugEnabled()) {
	    loggingService.debug("Destination address for Sub Query relay is :"
				 +dest_address.toString());
	  }
	  CmrRelay forwardedrelay = null;
	  forwardedrelay = factory.newCmrRelay(agentlookupquery, dest_address);
	  relay_uid_list.add(new OutStandingQuery(forwardedrelay.getUID()));
	  getBlackboardService().publishAdd(forwardedrelay);
	  if (loggingService.isDebugEnabled()) {
	    loggingService.debug(" Sub Query relay is :"
				 +forwardedrelay.toString());
	  }
	  modified=true;
	}
	if(modified) {
	  if (loggingService.isDebugEnabled()) {
	    loggingService.debug("Creating new Mapping query Object:");
	  }
	  if((mapping!=null)&&(mapping.getRelayUID().equals(relay.getUID()))) {
	    if (loggingService.isDebugEnabled()) {
	      loggingService.debug("Mapping query Object is not null && relay uid equals mapping uid:");
	    }
	    mapping.setQueryList(relay_uid_list);
	    getBlackboardService().publishChange(mapping);
	  }
	  else {
	    mapping=new QueryMapping(relay.getUID(), relay_uid_list);
	    getBlackboardService().publishAdd(mapping);
	  }
	}
      }
      else {
	if(newquery) {
	  if(myRole.equalsIgnoreCase("SecurityMnRManager-Society")) {
	    loggingService.debug("Creating QueryMapping object for new relay :"
				 + relay.toString());
	    mapping=new QueryMapping(relay.getUID(), null);
	    getBlackboardService().publishAdd(mapping);
	  }
	}
      }
      if (loggingService.isDebugEnabled()) {
	loggingService.debug("Finished query for subordinate managers.going to look for local sensor Agents"); 
      }
      String key=null;
      RegistrationAlert reg;
      ClusterIdentifier dest_address;
      response= findAgent(agentlookupquery,capabilities,true);
      if(response.isEmpty()) {
	if (loggingService.isDebugEnabled()) {
	  loggingService.debug("No Local agents are present with the capabilities. Returning");
	}
	relay.updateResponse(relay.getSource(),new MRAgentLookUpReply( new ArrayList()));
	getBlackboardService().publishChange(relay);
	return;
      }
      if (loggingService.isDebugEnabled()) {
	loggingService.debug("Local agents are present with the capabilities. no of agents are :"+
			     response.size());
      }
      Iterator response_iterator=response.iterator();
      ArrayList relay_uid_list=new ArrayList();
      while(response_iterator.hasNext()) {
	key=(String)response_iterator.next();
	//reg=(RegistrationAlert)capabilities.get(key);
	dest_address=new ClusterIdentifier(key);
	if (loggingService.isDebugEnabled()) {
	  loggingService.debug("Adding sensor agent to response :"+ dest_address.toString());
	}
	relay_uid_list.add(dest_address);
      }
      if (loggingService.isDebugEnabled()) {
	loggingService.debug("Update response is being done for source :"+relay.getSource().toString() );
	loggingService.debug("Update response is being done for relay :"+relay.toString());
      }
      relay.updateResponse(relay.getSource(),new MRAgentLookUpReply( relay_uid_list));
      getBlackboardService().publishChange(relay);
    }
    
    // Changed relays
    /*
      Currently not handling any relay change for relays that are not locally created    
      System.out.println("Changed relays of receiver plugin going to be executed:");
      Collection qcol= queryRelays.getChangedCollection();
      System.out.println("coll size in reci plugin is :"+qcol.size());
    
      iter = queryRelays.getChangedCollection().iterator();
      while (iter.hasNext()) {
      relay = (CmrRelay)iter.next();
      if (!relay.getSource().equals(myAddress)) {
	  
      Event oldCapabilities = findEventFrom(relay.getSource());
      if (oldCapabilities != null)
      getBlackboardService().publishRemove(oldCapabilities);
      loggingService.debug("printing replaced  relay which is not local:=========>"
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
      if((relay!=null)) {
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

  /**
   * @param query
   * @param caps
   * @param sensors - true when the search is performed on the local sensors.
   *                  false when the search is performed on the subordinate managers.
   */
  public List findAgent(MRAgentLookUp query, CapabilitiesObject caps, boolean sensors) {
  
    if(query==null) {
      loggingService.error("Query was null in findAgent. Sensor type :"+sensors);
      return new ArrayList();
    }
    if(caps==null) {
      loggingService.error("Capabilities was null returning");
      return  new ArrayList();
    }
    if(sensors){
      loggingService.debug("Looking for Local Sensors");
    }
    else {
      loggingService.debug("Looking for Managers");
    }
    
    //printhash(caps);
    Enumeration keys=caps.keys();
    Classification queryClassification=query.classification;
    Source querySource=query.source;
    Target queryTarget=query.target;
    String community=query.community;
    String role=query.role;
    String sourceOfAttack=query.source_agent;
    String targetOfAttack=query.target_agent;
    loggingService.debug("Query receive in  findAgent is :"+ query.toString());
    ArrayList commagents=new ArrayList();
    if((community!=null) && (role!=null)) {
      loggingService.debug("Searching with community and role combination :");
      commagents=(ArrayList)searchByCommunityAndRole(community,role);
    }
    else if((community==null)&&(role!=null))  {
      loggingService.debug("Searching with  role Only :");
      commagents=(ArrayList)searchByRole(role); 
      
    }
    else if((role==null)&&(community!=null) ) {
      loggingService.debug("Searching with  community Only :");
      commagents=(ArrayList)searchByCommunity(community); 
    }
    loggingService.debug("Printing result of community and role combination :");
    for(int i=0;i<commagents.size();i++) {
      loggingService.debug("Community and Role result at i:" + i
			   +". Agent is :" +(String)commagents.get(i));  
    }
    ArrayList classagents;
    ArrayList sourceagents;
    ArrayList targetagents;
    ArrayList sourceofAttackAgents;
    ArrayList targetofAttackAgents;
    ArrayList commonAgents=null;
    classagents=(ArrayList)searchByClassification(queryClassification,caps,sensors);
    loggingService.debug("Size of result with classification is " +classagents.size() );
    
    /*
      for(int i=0;i<classagents.size();i++) {
      loggingService.debug("classification result at i:"+i +" agent is :"+(String)classagents.get(i));  
      }
    */
    sourceagents=(ArrayList)searchBySource(querySource,caps,sensors);
    loggingService.debug("Size of result with source  is :" +sourceagents.size() );
    /*for(int i=0;i<sourceagents.size();i++) {
      loggingService.debug("source  result at i:"+i +" agent is :"+(String)classagents.get(i));  
      }
    */
    targetagents=(ArrayList)searchByTarget(queryTarget,caps,sensors);
    loggingService.debug("Size of result with target is :" +targetagents.size() );
    /* for(int i=0;i<targetagents.size();i++) {
       loggingService.debug("Target result at i:"+i +" agent is :"+(String)targetagents.get(i));  
       }
    */
    //loggingService.debug("Size of result with target is :" +targetagents.size() );
    sourceofAttackAgents=(ArrayList)searchBySourceOfAttack(sourceOfAttack,caps,sensors);
    loggingService.debug("Size of result with source of ATTACK  is :" +sourceofAttackAgents.size() );
    /*
      for(int i=0;i<sourceofAttackAgents.size();i++) {
      loggingService.debug("sourceofAttackAgents result at i:"+i +" agent is :"+(String)sourceofAttackAgents.get(i));  
      }
    */
    targetofAttackAgents=(ArrayList)searchByTargetOfAttack(targetOfAttack,caps,sensors);
    loggingService.debug("Size of result with target of ATTACK  is :" +targetofAttackAgents.size() );
    /*
      for(int i=0;i<targetofAttackAgents.size();i++) {
      loggingService.debug("targetofAttackAgents result at i:"+i +" agent is :"+(String)targetofAttackAgents.get(i));  
      }
    */
    if(((community!=null) || (role!=null))&& (commagents.isEmpty())) {
      loggingService.debug(" Community Rol combination is empty :");
      commonAgents=new ArrayList();
    }
    else {
      boolean iscomagentset=false;
      if((community!=null) || (role!=null)) {
	iscomagentset=true;
      }
      //if(queryClassification!=null) {
      //loggingService.debug("Query for classification was not null:");
      if(!iscomagentset) {
	commonAgents=classagents;
	iscomagentset=true;
      }
      else 
	commonAgents=(ArrayList)findCommanAgents(commagents,classagents);
      //}
      //if(querySource!=null) {
      //loggingService.debug("Query for Source was not null:");
      if(!iscomagentset) {
	commonAgents=sourceagents;
	iscomagentset=true;
      }
      else
	commonAgents=(ArrayList)findCommanAgents(commonAgents,sourceagents);
      //}
      //if(queryTarget!=null){
      //loggingService.debug("Query for Target  was not null:");
      if(!iscomagentset) {
	commonAgents=targetagents;
	iscomagentset=true;
      }
      else 
	commonAgents=(ArrayList)findCommanAgents(commonAgents,targetagents);
      //}
      //if(sourceOfAttack!=null) {
      //loggingService.debug("Query for SourceOf Attack  was not null:");
      if(!iscomagentset) {
	commonAgents=sourceofAttackAgents;
	iscomagentset=true;
      }
      else 
	commonAgents=(ArrayList)findCommanAgents(commonAgents,sourceofAttackAgents);
      //}
      //if(targetOfAttack!=null) {
      //loggingService.debug("Query for targetOfAttack was not null:");
      if(!iscomagentset) {
	commonAgents=targetofAttackAgents;
	iscomagentset=true;
      }
      else 
	commonAgents=(ArrayList)findCommanAgents(commonAgents,targetofAttackAgents);
      //}
    }
    loggingService.debug("Printing result of query:" + sensors);
    for(int i=0;i<commonAgents.size();i++) {
      loggingService.debug("result at i:"+i +" agent is :"+(String)commonAgents.get(i));  
    }
    return commonAgents;
    
  }
  
  
  public List findCommanAgents(List list1,List list2) {
    ArrayList commonList=new ArrayList();
    /*
      if(list1.isEmpty()) {
      return list2;
      }
      if(list2.isEmpty()){
      return list1;
      }
    */
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
    /*if(searchClassification==null) {
      return agentlist;
      }
    */
    if (loggingService.isDebugEnabled()) {
      if(searchClassification!=null){
	loggingService.debug("In find agent FUNCTION  query is :"+searchClassification.getName()+
			     "Origin  "+searchClassification.getOrigin() );
      }
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
	loggingService.debug("In capabilities object : Key is "+ key  );
      }
      Classification [] classifications=reg.getClassifications();
      if(classifications==null) {
	return agentlist;
      }
      if(searchClassification==null) {
	loggingService.debug("got search classification as null will return all sensors :");
	if(sensors) {
	  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
	    loggingService.debug("Analyzer id is :"+ reg.getAgentName());
	    loggingService.debug("Adding sensor key when classification is null :"+key);
	    agentlist.add(reg.getAgentName());
	  }
	}
	else {
	  loggingService.debug("Looking for Security  manager when classification is null :");
	  if((reg.getType().equals( IdmefMessageFactory.EnclaveMgrType))||
	     (reg.getType().equals( IdmefMessageFactory.SocietyMgrType))) {
	    loggingService.debug("Adding security manager  key when classification is null :"+key);
	    agentlist.add(key);
	  }
	}
	continue;
      }
      if(isClassificationPresent(searchClassification,classifications)) {
	loggingService.debug("Got calssification equal:" + key);
	if(sensors) {
	  loggingService.debug("Looking for sensors agents :");
	  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
	    loggingService.debug("Analyzer id is :"+ reg.getAgentName());
	    loggingService.debug("Adding sensor key :"+key);
	    agentlist.add(reg.getAgentName());
	  }
	}
	else {
	  loggingService.debug("Looking for Security  manager :");
	  if((reg.getType().equals( IdmefMessageFactory.EnclaveMgrType))||
	     (reg.getType().equals( IdmefMessageFactory.SocietyMgrType))) {
	    loggingService.debug("Adding security manager  key :"+key);
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
    /*
      if(searchSource==null) {
      return agentlist;
      }
    */
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("In  searchBySources FUNCTION  query is :"+searchSource);
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
	loggingService.debug(" in capabilities object : Key is "+ key );
      }
      sources=reg.getSources();
      if(searchSource==null) {
	if(sensors) {
	  loggingService.debug("Looking for sensors agents when query source is null :");
	  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
	    loggingService.debug(" adding sensor key when query source is null :"+key);
	    agentlist.add(reg.getAgentName());
	  }
	}
	else {
	  loggingService.debug("Looking for Security  managerwhen query source is null :");
	  if((reg.getType().equals( IdmefMessageFactory.EnclaveMgrType))||
	     (reg.getType().equals( IdmefMessageFactory.SocietyMgrType))) {
	    loggingService.debug("adding security manager  key when query source is null :"+key);
	    agentlist.add(key);
	  }
	}
	continue;
      }
      if(sources==null) {
	return agentlist;
      }
      if(isSourceORTargetPresent(searchSource,sources)) {
	loggingService.debug("Got source equal:" + reg.getType());
	if(sensors) {
	  loggingService.debug("Looking for sensors agents :");
	  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
	    loggingService.debug(" adding sensor key :"+key);
	    agentlist.add(reg.getAgentName());
	  }
	}
	else {
	  loggingService.debug("Looking for Security  manager :");
	  if((reg.getType().equals( IdmefMessageFactory.EnclaveMgrType))||
	     (reg.getType().equals( IdmefMessageFactory.SocietyMgrType))) {
	    loggingService.debug("adding security manager  key :"+key);
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
    /*if(searchTarget==null) {
      return agentlist;
      }
    */
    if (loggingService.isDebugEnabled()) {
      loggingService.debug(" in  searchByTargets FUNCTION  query is :"+searchTarget);
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
	loggingService.debug(" in capabilities object : Key is "+ key );
      }
      targets=reg.getTargets();
      if(searchTarget==null) {
	if(sensors) {
	  loggingService.debug("Looking for sensors agents when query target is null:");
	  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
	    loggingService.debug(" adding sensor key when query target is null :"+key);
	    agentlist.add(reg.getAgentName());
	  }
	}
	else {
	  loggingService.debug("Looking for Security  manager when query target is null:");
	  if((reg.getType().equals( IdmefMessageFactory.EnclaveMgrType))||
	     (reg.getType().equals( IdmefMessageFactory.SocietyMgrType))) {
	    loggingService.debug("Adding security manager  key when query target is null :"+key);
	    agentlist.add(key);
	  }
	}
	continue;
      }
      if(targets==null) {
	return agentlist;
      } 
      if(isSourceORTargetPresent(searchTarget,targets)) {
	loggingService.debug(" Got source equal:" + reg.getType());
	if(sensors) {
	  loggingService.debug("Looking for sensors agents :");
	  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
	    loggingService.debug(" adding sensor key :"+key);
	    agentlist.add(reg.getAgentName());
	  }
	}
	else {
	  loggingService.debug("Looking for Security  manager :");
	  if((reg.getType().equals( IdmefMessageFactory.EnclaveMgrType))||
	     (reg.getType().equals( IdmefMessageFactory.SocietyMgrType))) {
	    loggingService.debug("Adding security manager  key :"+key);
	    agentlist.add(key);
	  }
	  
	}
      }
    }
    return agentlist;
  }
  
  private List searchBySourceOfAttack(String agentname,CapabilitiesObject caps, boolean sensors) {
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    Source []sources =null;
    AdditionalData [] additionaldatas=null;
    AdditionalData data=null;
    ArrayList agentlist=new ArrayList();
    /*if(agentname==null) {
      return agentlist;
      }
    */
    if (loggingService.isDebugEnabled()) {
      loggingService.debug(" in  searchBySourcesofattack  FUNCTION  query is :"+agentname);
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
	loggingService.debug(" in capabilities object : Key is "+ key );
      }
      sources=reg.getSources();
      additionaldatas=reg.getAdditionalData();
      if(agentname==null) {
	if(sensors) {
	  loggingService.debug("Looking for sensors agents when source of attack is null  :");
	  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
	    loggingService.debug(" adding sensor key when source of attack is null:"+key);
	    agentlist.add(reg.getAgentName());
	  }
	}
	else {
	  loggingService.debug("Looking for Security  managerwhen source of attack is null :");
	  if((reg.getType().equals( IdmefMessageFactory.EnclaveMgrType))||
	     (reg.getType().equals( IdmefMessageFactory.SocietyMgrType))) {
	    loggingService.debug(" adding security manager  keywhen source of attack is null  :"+key);
	    agentlist.add(key);
	  }
	}
	continue;
      }
      if(sources==null) {
	return agentlist;
      }
      if(additionaldatas==null) {
	return agentlist;
      }
      for(int i=0;i<additionaldatas.length;i++) {
	data=additionaldatas[i];
	org.cougaar.core.security.monitoring.idmef.Agent agentinfo=null;
	if((data.getType().equalsIgnoreCase("xml"))&&(data.getXMLData()!=null)) {
	  if(data.getXMLData() instanceof org.cougaar.core.security.monitoring.idmef.Agent){ 
	    agentinfo=( org.cougaar.core.security.monitoring.idmef.Agent)data.getXMLData();
	  }
	}
	if(agentinfo!=null) {
	  if(agentname.trim().equals(agentinfo.getName())) {
	    String [] ref=agentinfo.getRefIdents();
	    if(ref!=null) {
	      String refstring=null;
	      boolean found=true;
	      for(int x=0;x<ref.length;x++) {
		refstring=ref[x];
		for(int z=0;z<sources.length;z++) {
		  if(refstring.trim().equals(sources[z].getIdent().trim())) {
		    found=true;
		    break;
		  }
		}
		if(found)
		  break;
	      }
	      if(found) {
		if(sensors) {
		  loggingService.debug("Looking for sensors agents :");
		  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
		    loggingService.debug(" adding sensor key :"+key);
		    agentlist.add(reg.getAgentName());
		  }
		}
		else {
		  loggingService.debug("Looking for Security  manager :");
		  if((reg.getType().equals( IdmefMessageFactory.EnclaveMgrType))||
		     (reg.getType().equals( IdmefMessageFactory.SocietyMgrType))) {
		    loggingService.debug(" adding security manager  key :"+key);
		    agentlist.add(key);
		  }
	  	}
		
	      }
	    }
	  }
	}
      }
    }
    return agentlist;
  }
  
  private List searchByTargetOfAttack(String agentname,CapabilitiesObject caps, boolean sensors) {
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    Target [] targets =null;
    AdditionalData [] additionaldatas=null;
    AdditionalData data=null;
    ArrayList agentlist=new ArrayList();
    /*if(agentname==null) {
      return agentlist;
      }
    */
    if (loggingService.isDebugEnabled()) {
      loggingService.debug(" in  searchByTargetofattack  FUNCTION  query is :"+agentname);
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
	loggingService.debug(" in capabilities object : Key is "+ key );
      }
      targets=reg.getTargets();
      additionaldatas=reg.getAdditionalData();
      if(agentname==null) {
	if(sensors) {
	  loggingService.debug("Looking for sensors agents when target of attack is null  :");
	  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
	    loggingService.debug(" adding sensor key when target of attack is null :"+key);
	    agentlist.add(reg.getAgentName());
	  }
	}
	else {
	  loggingService.debug("Looking for Security  manager when target of attack is null :");
	  if((reg.getType().equals( IdmefMessageFactory.EnclaveMgrType))||
	     (reg.getType().equals( IdmefMessageFactory.SocietyMgrType))) {
	    loggingService.debug("Adding security manager  key when target of attack is null:"+key);
	    agentlist.add(key);
	  }
	}
	continue;
      }
      if(targets==null) {
	return agentlist;
      }
      if(additionaldatas==null) {
	return agentlist;
      }
      for(int i=0;i<additionaldatas.length;i++) {
	data=additionaldatas[i];
	org.cougaar.core.security.monitoring.idmef.Agent agentinfo=null;
	if((data.getType().equalsIgnoreCase("xml"))&&(data.getXMLData()!=null)) {
	  if(data.getXMLData() instanceof org.cougaar.core.security.monitoring.idmef.Agent){ 
	    agentinfo=( org.cougaar.core.security.monitoring.idmef.Agent)data.getXMLData();
	  }
	}
	if(agentinfo!=null) {
	  if(agentname.trim().equals(agentinfo.getName())) {
	    String [] ref=agentinfo.getRefIdents();
	    if(ref!=null) {
	      String refstring=null;
	      boolean found=true;
	      for(int x=0;x<ref.length;x++) {
		refstring=ref[x];
		for(int z=0;z<targets.length;z++) {
		  if(refstring.trim().equals(targets[z].getIdent().trim())) {
		    found=true;
		    break;
		  }
		}
		if(found)
		  break;
	      }
	      if(found) {
		if(sensors) {
		  loggingService.debug("Looking for sensors agents :");
		  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
		    loggingService.debug(" adding sensor key :"+key);
		    agentlist.add(reg.getAgentName());
		  }
		}
		else {
		  loggingService.debug("Looking for Security  manager :");
		  if((reg.getType().equals( IdmefMessageFactory.EnclaveMgrType))||
		     (reg.getType().equals( IdmefMessageFactory.SocietyMgrType))) {
		    loggingService.debug("Adding security manager  key :"+key);
		    agentlist.add(key);
		  }
	  	}
		
	      }
	    }
	  }
	}
      }
    }
    return agentlist;
    // return new ArrayList();
  }
  
  private String getMySecurityCommunity() {
    String mySecurityCommunity=null;
    if(communityService==null) {
      loggingService.error("Community Service is null" +myAddress.toString()); 
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
      loggingService.warn("Search  for my Security Community FAILED" +myAddress.toString()); 
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
      if(role.equalsIgnoreCase("SecurityMnRManager-Society")) {
	societymgr=true;
      }
    }
    if(enclavemgr) {
      myRole="SecurityMnRManager-Enclave"; 
    }
    if(societymgr ) {
      myRole="SecurityMnRManager-Society";
    }
    if(enclavemgr && societymgr) {
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
    if((existingclassification.getOrigin().trim().equalsIgnoreCase(newclassification.getOrigin().trim()))
       &&(existingclassification.getName().trim().equalsIgnoreCase(newclassification.getName().trim()))) {
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
      /*loggingService.debug("current classification :"+ classificationtoString(currentclassification));
	loggingService.debug("query classification :"+ classificationtoString(queryclassification));
      */
      if(areClassificationsEqual(currentclassification,queryclassification)){
	isclassification=true;
	return isclassification;
      }
    }
    return isclassification  ;
  }
  
  public boolean isSourceORTargetPresent(Object inquery,Object[] inObjectArray) {
    boolean ispresent=false;
    loggingService.debug("Size of source or target is :"+ inObjectArray.length);
    for(int i=0;i<inObjectArray.length;i++) {
      if(areSourceORTargetEqual(inObjectArray[i],inquery)){
	ispresent=true;
	return ispresent;
      }
      else {
	loggingService.debug(" source or Target is not present :");
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
      boolean nameequal=false;
      boolean addressequal=false;
      boolean categoryequal=false;
      String queryname=queryNode.getName();
      String existingname=existingNode.getName();
      Address queryAddress []=queryNode.getAddresses();
      Address existingAddress[]=existingNode.getAddresses();
      String queryCategory=queryNode.getCategory();
      String existingCategory=existingNode.getCategory();
      if(queryname==null) {
	nameequal=true;
	//loggingService.debug("In Idmef node queryname was null:");	
      }
      if((queryname!=null)&&(existingname!=null)) {
	if(queryname.trim().equals(existingname.trim())) {
	  //loggingService.debug("In Idmef node queryname are equal:");
	  nameequal=true;
	}
      }
      if(queryAddress==null) {
	addressequal=true;
	//loggingService.debug("In Idmef node queryAddress was null:");
      }
      if((queryAddress!=null)&&(existingAddress!=null)) {
	loggingService.debug("In Idmef queryAddress && existing address is not  null:");
	if(existingAddress.length>=queryAddress.length) {
	  Address inqueryAddress=null;
	  for(int i=0;i<queryAddress.length;i++) {
	    inqueryAddress=queryAddress[i];
	    if(!containsAddress(inqueryAddress,existingAddress)) {
	      addressequal=false;
	      break;
	    }
	  }
	  addressequal=true;
	  //loggingService.debug("In Idmef node address are equal :");
	}
	
      }
      if(queryCategory==null) {
	//loggingService.debug("In Idmef node queryCategory was null:");
	categoryequal=true;
      }
      if((queryCategory !=null) && (existingCategory!=null)) {
	//loggingService.debug("query category is :"+ queryCategory);
	//loggingService.debug("existing Category category is :"+ existingCategory);
	if(queryCategory.trim().equals(existingCategory.trim())) {
	  loggingService.debug("In Idmef node queryCategory are equal :");
	  categoryequal=true;
	}
      }
      if(existingCategory==null){
	//loggingService.debug("existing Category category is NULL :");
      }
      
      if( nameequal &&  addressequal && categoryequal) {
	//loggingService.debug("In Idmef node are equal :");
	nodeequal=true;
      }
      
    }
    else if((existingNode==null)&&(queryNode==null)){
      nodeequal=true;
      //loggingService.debug("In Idmef node are equal :");
    }
    else if(queryNode==null) {
      nodeequal=true;
    }
          
    if((existingUser!=null)&&(queryUser!=null)){
      UserId [] queryUserId=queryUser.getUserIds();
      UserId [] existingUserId=existingUser.getUserIds();
      if(queryUserId==null) {
	//loggingService.debug("In Idmef query User  is null  :");
	userequal =true;
      }
      if((queryUserId !=null) &&(existingUserId!=null)) {
	if(existingUserId.length>=queryUserId.length) {
	  UserId userid=null;
	  for(int i=0;i<queryUserId.length;i++) {
	    userid=queryUserId[i];
	    if(!containsUserId(userid,queryUserId)) {
	      userequal=false;
	      break;
	    }
	  }
	  userequal=true;
	  //loggingService.debug("In Idmef query User  is true  :");
	}
      }
    }
    else if((existingUser==null)&&(queryUser==null)){
      //loggingService.debug("In Idmef query User  is true  :");
      userequal=true;
    }
    else if(queryUser==null){
      userequal=true;
    }
    
    if((existingService!=null)&&(queryService!=null)){
      String existingServiceName=existingService.getName();
      String queryServiceName=queryService.getName();
      Integer existingPort=existingService.getPort();
      Integer queryPort=queryService.getPort();
      String existingPortList=existingService.getPortlist();
      String queryPortList=queryService.getPortlist();
      String existingProtocol=existingService.getProtocol();
      String queryprotocol=queryService.getProtocol();
      boolean nameequal=false;
      boolean portequal=false;
      boolean portlistequal=false;
      boolean protocolequal=false;
      if(queryServiceName==null) {
	nameequal=true;
      }
      if((existingServiceName!=null) && (queryServiceName!=null)) {
	if(existingServiceName.trim().equals(queryServiceName.trim())) {
	  nameequal=true;
	}
      }
      if(queryPort==null) {
	portequal=true;
      }
      if((existingPort!=null) &&(queryPort!=null)) {
	if(existingPort.intValue()==queryPort.intValue()) {
	  portequal=true;
	}
      }
      if(queryPortList==null) {
	portlistequal =true;
      }
      if((existingPortList!=null)&&(queryPortList!=null)) {
	if(existingPortList.trim().equals(queryPortList.trim())) {
	  portlistequal=true;
	}
      }
      if(queryprotocol==null) {
	protocolequal=true;
      }
      if((existingProtocol!=null) &&(queryprotocol!=null)) {
	if(existingProtocol.trim().equals(queryprotocol.trim())) {
	  protocolequal=true;
	}
      }
	
      if( nameequal &&  portequal &&  portlistequal &&  protocolequal) {
	serviceequal=true;
	//loggingService.debug("In Idmef serviceequal  is true  :");
      }
    }
    else if((existingService==null)&&(queryService==null)){
      //loggingService.debug("In Idmef serviceequal  is true  :");
      serviceequal=true;
    }
    else if(queryService==null) {
      serviceequal=true;
    }
    
    if((existingProcess!=null)&&(queryProcess!=null)){
      String existingPath=existingProcess.getPath();
      String queryPath=queryProcess.getPath();
      String existingName=existingProcess.getName();
      String queryName=queryProcess.getName();
      boolean processNameequal=false;
      boolean processPathequal=false;
      if(queryPath==null) {
	processPathequal=true;
      }
      if((existingPath!=null) &&(queryPath!=null)) {
	if(existingPath.trim().equals(queryPath.trim())) {
	  processPathequal=true;
	}
      }
      if(queryName==null) {
	processNameequal=true;
      }
      if((existingName!=null) &&(queryName!=null)) {
	if(existingName.trim().equals(queryName.trim())) {
	  processNameequal=true;
	}
      }
      if(processPathequal && processNameequal) {
	processequal=true;
	//loggingService.debug("In Idmef processequal  true :");
      }
    }
    else if((existingProcess==null)&&(queryProcess==null)){
      //loggingService.debug("In Idmef processequal  true :");
      processequal=true;
    }
    else if(queryProcess==null) {
      processequal=true;
    }
    if( nodeequal &&  userequal &&  serviceequal &&  processequal) {
      loggingService.debug("Either source or target is equal  :");
      equal=true;
    }
    return equal;
     
  }
 
  public boolean containsUserId(UserId inUserId, UserId [] arrayUserId) {
    boolean contains=false;
    UserId userid;
    if(inUserId==null) {
      return contains;
    }
    boolean nameequal=false;
    boolean numberequal=false;
    if(arrayUserId!=null) {
      for(int i=0;i<arrayUserId.length;i++) {
	userid=arrayUserId[i];
	String inName=inUserId.getName();
	String name=userid.getName();
	Integer innumber=inUserId.getNumber();
	Integer number=userid.getNumber();
	if((inName!=null)&& (name!=null)) {
	  if(inName.trim().equals(name.trim())) {
	    nameequal=true;
	  }
	}
	if((innumber!=null)&&(number!=null)) {
	  if(innumber.intValue()==number.intValue()) {
	    numberequal=true;
	  }
	}
	if(nameequal && numberequal) {
	  contains=true;
	  return contains;
	}
	    
      }
    }
    return contains;
  }
    
  public boolean containsAddress(Address anAddress, Address [] arrayAddress) {
    boolean contains=false;
    Address address;
    if(anAddress==null) {
      return contains;
    }
    if(arrayAddress!=null) {
      //myAddresses=this.getAddresses();
      for(int i=0;i<arrayAddress.length;i++) {
	address=arrayAddress[i];
	String stringaddress=address.getAddress();
	String inaddress=anAddress.getAddress();
	String category=address.getCategory();
	String incategory=anAddress.getCategory();
	boolean addressequal=false;
	boolean categoryequal=false;
	if((stringaddress!=null)&& (inaddress!=null)) {
	  if(stringaddress.trim().equals(inaddress.trim())) {
	    addressequal=true;
	  }
	}
	else if((stringaddress==null)&& (inaddress==null)) {
	  addressequal=true;
	}
	if((category!=null)&&(incategory!=null))  {
	  if(category.trim().equals(incategory.trim())) {
	    categoryequal=true;
	  }
	}
	else if((category==null)&&(incategory==null))  {
	  categoryequal=true;
	}
	if(addressequal && categoryequal) {
	  contains=true;
	  return contains;
	}
      }
    }
    return contains;
  }
  
  public boolean isRelayQueryOriginator(UID givenUID, Collection queryMappingCol ) {
    boolean isoriginator=false;
    QueryMapping querymapping=null;
    if(!queryMappingCol.isEmpty()){
      if (loggingService.isDebugEnabled()) {
	loggingService.debug("Going to find if this relay id is originator of query :"); 
      }
      Iterator iter=queryMappingCol.iterator();
      while(iter.hasNext()) {
	querymapping=(QueryMapping)iter.next();
	if(querymapping.getRelayUID().equals(givenUID)) {
	  isoriginator=true;
	  return isoriginator;
	}
      }
    }
    return isoriginator;
  }
  
  public boolean isRelaySubQuery(UID givenUID, Collection queryMappingCol ) {
    QueryMapping foundqMapping=null;
    ArrayList relayList;
    OutStandingQuery outstandingq;
    boolean issubquery=false;
    //QueryMapping tempqMapping;
    if(!queryMappingCol.isEmpty()){
      if (loggingService.isDebugEnabled()) {
	loggingService.debug("Going to find uid from list of Query mapping Objects on bb"+queryMappingCol.size()); 
      }
      Iterator iter=queryMappingCol.iterator();
      while(iter.hasNext()) {
	foundqMapping=(QueryMapping)iter.next();
	relayList=foundqMapping.getQueryList();
	if(relayList==null) {
	  return false;
	}
	for(int i=0;i<relayList.size();i++) {
	  outstandingq=(OutStandingQuery)relayList.get(i);
	  if(outstandingq.getUID().equals(givenUID)) {
	    if (loggingService.isDebugEnabled()) {
	      loggingService.debug(" Found given uid :"+ givenUID +" in object with UID :"+outstandingq.getUID());
	    }
	    issubquery=true;
	    return issubquery;
	  }
	}
      }
    } 
    else {
      return issubquery;
    }
    return issubquery;
  }
  
  public QueryMapping findQueryMappingFromBB(UID givenUID, Collection queryMappingCol ) {
    QueryMapping foundqMapping=null;
    ArrayList relayList;
    OutStandingQuery outstandingq;  
    //QueryMapping tempqMapping;
    if(!queryMappingCol.isEmpty()){
      if (loggingService.isDebugEnabled()) {
	loggingService.debug("Going to find uid from list of Query mapping Objects on bb"+queryMappingCol.size()); 
      }
      Iterator iter=queryMappingCol.iterator();
      while(iter.hasNext()) {
	foundqMapping=(QueryMapping)iter.next();
	if(foundqMapping.getRelayUID().equals(givenUID)) {
	  return foundqMapping;
	}
	relayList=foundqMapping.getQueryList();
	if(relayList==null) {
	  return null;
	}
	for(int i=0;i<relayList.size();i++) {
	  outstandingq=(OutStandingQuery)relayList.get(i);
	  if(outstandingq.getUID().equals(givenUID)) {
	    if (loggingService.isDebugEnabled()) {
	      loggingService.debug(" Found given uid :"+ givenUID +" in object with UID :"+outstandingq.getUID());
	    }
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
  public void printhash(CapabilitiesObject cap) {
    Enumeration keys=cap.keys();
    String key=null;
    RegistrationAlert registration=null;
    loggingService.debug(" CAPABILITIES OBJECT IN ADDRESS :"+myAddress.toString());
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      if (loggingService.isDebugEnabled()) {
	loggingService.debug(" KEY IN CAPABILITIES OBJECT IS :"+key);
      }
      registration=(RegistrationAlert)cap.get(key);
      loggingService.debug(" data of  alert is :"+registration.toString());
    }
    
  }
  
   
}
