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


class QueryRespondRelayPredicate implements  UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret = ( relay.getContent() instanceof MRAgentLookUp );
    }
    return ret;
  }
}

class QueryMappingObjectPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof  QueryMapping ) {
      return true;
    }
    return ret;
  }
}


public class MnRQueryResponderPlugin extends ComponentPlugin {

  // The domainService acts as a provider of domain factory services
  private DomainService domainService = null;
  private IncrementalSubscription queryRelays;
  private IncrementalSubscription querymapping;
  private final int firstobject=0;
  private LoggingService loggingService;
  private MessageAddress myAddress=null;
  private Object param;
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
    myAddress = getBindingSite().getAgentIdentifier();
    loggingService.debug("setupSubscriptions of MnRQueryResponderPlugin called :"+ myAddress.toString());
    queryRelays= (IncrementalSubscription)getBlackboardService().subscribe
      (new QueryRespondRelayPredicate());
    querymapping= (IncrementalSubscription)getBlackboardService().subscribe
      (new QueryMappingObjectPredicate());
    
  }
  protected void execute () {
    updateRelayedQueryResponse();
  }
  /*
   */
  protected void updateRelayedQueryResponse() {
    QueryMapping mapping;
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    Iterator iter;
    CmrRelay relay;
    loggingService.debug("updateRelayedQueryResponse of MnRQueryResponderPlugin called !!!!!!!!!!! :"+ myAddress); 
    if(queryRelays.hasChanged()) {
      loggingService.debug("queryRelays has changed in MnRQueryResponderPlugin at  :"+myAddress); 
      Collection  querymapping_col=querymapping.getCollection();
      if (loggingService.isDebugEnabled())  {
	loggingService.debug(" collection size of query mapping in MnRQueryResponderPlugin :"+ querymapping_col.size() );
	loggingService.debug(" Going to get iterator for query relays:");
      }
      Collection cols=queryRelays.getChangedCollection();
      loggingService.debug("query relays changed collection size in MnRQueryResponderPlugin is  "+ cols.size());
      iter = cols.iterator();
      while (iter.hasNext()) {
	relay = (CmrRelay)iter.next();
	if (relay.getSource().equals(myAddress)) {
	  if (loggingService.isDebugEnabled())
	    loggingService.debug(" Got query relay with source as my address :");
	  if(relay.getResponse()!=null) {
	    if (loggingService.isDebugEnabled()) {
	      loggingService.debug(" Got response  :"+relay.getResponse().toString());
	      loggingService.debug(" Going to look for query mapping object with UID :"+ relay.getUID()); 
	    }
	    mapping=findQueryMappingFromBB(relay.getUID(),querymapping_col);
	    if(mapping!=null) {
	      ArrayList list=mapping.getQueryList(); 
	      OutStandingQuery outstandingquery;
	      boolean modified=true;
	      for(int i=0;i<list.size();i++) {
		outstandingquery=(OutStandingQuery)list.get(i);
		if(outstandingquery.getUID().equals(relay.getUID())) {
		  list.remove(i);
		  outstandingquery.setOutStandingQuery(false);
		  list.add(i,outstandingquery);
		  mapping.setQueryList(list);
		  break;
		}
	      }
	      boolean anyOutStandingquery=findQueryStatus(mapping);
	      if(!anyOutStandingquery) {
		if (loggingService.isDebugEnabled())
		  loggingService.debug(" updating response in responder plugin with no outstanding query :");
		UpdateResponse(mapping);
	      }
	    }
	    else {
	      if (loggingService.isDebugEnabled())
		loggingService.debug(" Could not find Query mapping object for UId :"+ relay.getUID());
	    }
	  }
	  else {
	    if (loggingService.isDebugEnabled())
	      loggingService.debug("got relay as my address but response is null :"+relay.toString()); 
	  }
	}
	else{
	  if (loggingService.isDebugEnabled())
	    loggingService.debug(" i'm not the source and I want relay with me as source :"+relay.toString());
	}
      }
      if (loggingService.isDebugEnabled())
	loggingService.debug(" Done with update relay from responder plugin:");
    }
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
 
  public boolean findQueryStatus(QueryMapping map) {
    boolean outStandingQuery=true;
    ArrayList list=(ArrayList)map.getQueryList();
    OutStandingQuery outstandingquery;
    for(int i=0;i<list.size();i++) {
      outstandingquery=(OutStandingQuery)list.get(i);
      outStandingQuery=outstandingquery.isQueryOutStanding();
    }
    return outStandingQuery;
  }
  
  public void UpdateResponse (QueryMapping map) {
    CmrRelay relay;
    UID uid;
    CmrRelay response_relay;
    MRAgentLookUpReply reply;
    ArrayList agentList=new ArrayList();
    relay=findCmrRelay(map.getRelayUID());
    if(relay!=null) {
      if (loggingService.isDebugEnabled())
	loggingService.debug("update response called for realy :"+relay.toString());
      ArrayList list=map.getQueryList();
      OutStandingQuery outstandingquery;
      for(int i=0;i<list.size();i++) {
	outstandingquery=(OutStandingQuery)list.get(i);
	if (loggingService.isDebugEnabled())
	  loggingService.debug(" finding relay for outstanding query :");
	response_relay=findCmrRelay(outstandingquery.getUID());
	if(response_relay!=null) {
	  reply=(MRAgentLookUpReply ) response_relay.getResponse();
	  agentList.addAll(reply.getAgentList());
	}
	else {
	  if (loggingService.isDebugEnabled())
	    loggingService.debug(" Could not find UID:"+ outstandingquery.getUID()+
				 "in Update response of agent :"+myAddress.toString());
	}
      }
      reply=new MRAgentLookUpReply(agentList);
      relay.updateResponse(relay.getSource(),reply);
      getBlackboardService().publishChange(relay);
      getBlackboardService().publishChange(map);
    }
    else {
      if (loggingService.isDebugEnabled())
	loggingService.debug(" could not find relay for :"+map.getRelayUID().toString());
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
}
