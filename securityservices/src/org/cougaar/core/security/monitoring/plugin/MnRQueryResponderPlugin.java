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
import org.cougaar.core.mts.MessageAddress;
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
import java.util.ListIterator;


class QueryRespondRelayPredicate implements  UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret =(( relay.getContent() instanceof MRAgentLookUp )&&(relay.getResponse() instanceof MRAgentLookUpReply));
    }
    return ret;
  }
}
class ALLQueryRelayPredicate implements  UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret =(( relay.getContent() instanceof MRAgentLookUp ));
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
  private IncrementalSubscription queryResponse;
  private IncrementalSubscription allqueryRelays;
  private IncrementalSubscription querymapping;
  private final int firstobject=0;
  private LoggingService loggingService;
  private MessageAddress myAddress=null;
  private Object param;
  // private MessageAddress destAddress;

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
    myAddress = getAgentIdentifier();
    loggingService.debug("setupSubscriptions of MnRQueryResponderPlugin called :"+ myAddress.toString());
    queryResponse= (IncrementalSubscription)getBlackboardService().subscribe
      (new QueryRespondRelayPredicate());
    querymapping= (IncrementalSubscription)getBlackboardService().subscribe
      (new QueryMappingObjectPredicate());
    allqueryRelays=(IncrementalSubscription)getBlackboardService().subscribe
      (new ALLQueryRelayPredicate());
    
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
    loggingService.debug("updateRelayedQueryResponse of MnRQueryResponderPlugin called:"
        + myAddress ); 
    if(queryResponse.hasChanged()) {
      loggingService.debug("queryRelays has changed in MnRQueryResponderPlugin at:"
          +myAddress); 
      Collection  querymapping_col=querymapping.getCollection();
      if (loggingService.isDebugEnabled())  {
        loggingService.debug(" collection size of query mapping in MnRQueryResponderPlugin:"
            + querymapping_col.size() );
        loggingService.debug(" Going to get iterator for query relays:");
      }
      Collection cols=queryResponse.getChangedCollection();
      loggingService.debug("query relays changed collection size in MnRQueryResponderPlugin is "
          + cols.size());
      iter = cols.iterator();
      while (iter.hasNext()) {
        querymapping_col=querymapping.getCollection();
        relay = (CmrRelay)iter.next();
        if (relay.getSource().equals(myAddress)) {
          if (loggingService.isDebugEnabled()) {
            loggingService.debug(" Got query relay with source as my address :" + relay.toString());
          }
          if(relay.getResponse() != null) {
            if (loggingService.isDebugEnabled()) {
              loggingService.debug("Relay with response is :"+relay.toString());
              loggingService.debug(" Got response  :"+relay.getResponse().toString());
              loggingService.debug(" Going to look for query mapping object with UID :"+ relay.getUID()); 
            }
            boolean isoriginator=isRelayQueryOriginator(relay.getUID(),querymapping_col);
            /*if(isoriginator) {
              loggingService.debug("Relay received is the originator of the query :"+ relay.toString());
              continue;
              }
             */
            mapping=findQueryMappingFromBB(relay.getUID(),querymapping_col);
            if(mapping!=null) {
              if(mapping.isResultPublished()) {
                if (loggingService.isDebugEnabled())  {
                  loggingService.debug("Relay received has a mapping object with result published as true :" +mapping.toString());
                }
                continue;
              }
              ArrayList list=mapping.getQueryList(); 
              OutStandingQuery outstandingquery;
              boolean modified=false;
              if(list!=null) {
                for(int i=0;i<list.size();i++) {
                  outstandingquery=(OutStandingQuery)list.get(i);
                  loggingService.debug("Ouststanding query uid "+outstandingquery.getUID() + "outstanding object is :"+ outstandingquery.toString());
                  if(outstandingquery.getUID().equals(relay.getUID())) {
                    loggingService.debug("Receive Response for Ouststanding query uid "+outstandingquery.getUID() + "Current relay id is :"+relay.getUID() );
                    list.remove(i);
                    outstandingquery.setOutStandingQuery(false);
                    list.add(i,outstandingquery);
                    mapping.setQueryList(list);
                    modified=true;
                  }
                }
                boolean anyOutStandingquery=findQueryStatus(mapping);
		
                if(!anyOutStandingquery) {
                  // All the replies have been received.
                  // Update the response and send it back to the originator.
                  if (loggingService.isDebugEnabled()) {
                    loggingService.debug("Updating response in responder plugin with no outstanding query");
                  }
                  updateResponse(mapping);
                }
                if(modified) {
                  getBlackboardService().publishChange(mapping);
                }
              }
              else {
                if (loggingService.isDebugEnabled()) {
                  loggingService.debug(" Relay List in Query Mapping is NULL :");
                }
              }
            }
            else {
              if (loggingService.isDebugEnabled()) {
                loggingService.debug(" Could not find Query mapping object for UId :"+ relay.getUID());
              }
            }
          }
          else {
            if (loggingService.isDebugEnabled()) {
              loggingService.debug("got relay as my address but response is null:"
                  +relay.toString());
            }
          }
        }
        else{
          if (loggingService.isDebugEnabled()) {
            loggingService.debug(" i'm not the source and I want relay with me as source :"+relay.toString());
          }
        }
      }
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(" Done with update relay from responder plugin:");
      }
    }
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
 
  public boolean findQueryStatus(QueryMapping map) {
    boolean outStandingQuery=false;
    ArrayList list=(ArrayList)map.getQueryList();
    OutStandingQuery outstandingquery;
    if(list==null) {
      return outStandingQuery;
    }
    for(int i=0;i<list.size();i++) {
      outstandingquery=(OutStandingQuery)list.get(i);
      boolean currentstatus=outstandingquery.isQueryOutStanding();
      if(currentstatus){
        outStandingQuery=currentstatus;
        return outStandingQuery;
      }
    }
    return outStandingQuery;
  }
  
  public void updateResponse (QueryMapping map) {
    CmrRelay relay; // Original query
    UID uid;
    CmrRelay response_relay; // subquery sent to lower level managers
    MRAgentLookUpReply reply;
    List agentList=new ArrayList();
    relay=findCmrRelay(map.getRelayUID());
    if(relay!=null) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("Update response called for relay :"+relay.toString());
      }
      ArrayList list=map.getQueryList();
      if(list==null) {
        reply=new MRAgentLookUpReply(agentList);
        map.setResultPublished(true);
        relay.updateResponse(relay.getSource(),reply);
        getBlackboardService().publishChange(relay);
        getBlackboardService().publishChange(map);
        loggingService.debug("Got the mapping list as null setting the relay response as empty:");
        return;
      }
      OutStandingQuery outstandingquery;
      //boolean completed=false;
      for(int i=0;i<list.size();i++) {
        outstandingquery=(OutStandingQuery)list.get(i);
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("Finding relay for outstanding query");
        }
        response_relay=findCmrRelay(outstandingquery.getUID());
        if(response_relay!=null) {
          reply=(MRAgentLookUpReply ) response_relay.getResponse();
          if (reply != null) {
            if( reply.getAgentList()!=null) {
              agentList=mergeResponse(agentList, reply.getAgentList());
              //agentList.addAll( reply.getAgentList());
            }
          }
          else {
            loggingService.error("Lookup query marked as completed, but at least one response is null. "
                + "Subquery:" + response_relay.toString()
                + ". Original query:" + relay.toString());
          }
        }
        else {
	  
          if (loggingService.isDebugEnabled())
            loggingService.debug(" Could not find UID:"+ outstandingquery.getUID()+
                "in Update response of agent :"+myAddress.toString());
        }
      }
      reply=new MRAgentLookUpReply(agentList);
      map.setResultPublished(true);
      relay.updateResponse(relay.getSource(),reply);
      getBlackboardService().publishChange(relay);
      getBlackboardService().publishChange(map);
    }
    else {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("Could not find relay for :"+map.getRelayUID().toString());
      }
    }
  }
  public List  mergeResponse(List existingList, List newList) {
    if(existingList==null) {
      loggingService.error("Response Agent list should have been created in updateResponse :");
    }
    if(newList==null) {
      return existingList;
    }
    ArrayList returnList=new ArrayList();
    ListIterator existinglistiterator=existingList.listIterator();
    MessageAddress agentid=null;
    boolean ispresent=false;
    while(existinglistiterator.hasNext()) {
      agentid=(MessageAddress)existinglistiterator.next();
      if(agentid!=null) {
        ispresent=isAgentInList(agentid.getAddress(),returnList);
        if(!ispresent) {
          returnList.add(agentid);
        }
      }
      
    }
    ListIterator listiterator=newList.listIterator();
    while(listiterator.hasNext()) {
      agentid=(MessageAddress)listiterator.next();
      if(agentid!=null) {
        ispresent=isAgentInList(agentid.getAddress(),returnList);
        if(!ispresent) {
          returnList.add(agentid);
        }
      }
    }
    return returnList;
  }
  
  public boolean isAgentInList(String agent ,List list) {
    boolean present=false;
    if(list==null) {
      loggingService.error(" List should not be null It can be empty :");
      return true;
    }
    if(agent==null) {
      return true;
    }
    ListIterator listiterator=list.listIterator();
    MessageAddress agentid=null;
    while(listiterator.hasNext()) {
      agentid=(MessageAddress)listiterator.next();
      if(agentid!=null){
        if(agentid.getAddress().equalsIgnoreCase(agent)){
          present=true;
          return present;
        }
      }
    }
    return present;
    
  }
    
  public CmrRelay  findCmrRelay (UID key) {
    CmrRelay relay=null;
    Collection relaycollection=allqueryRelays.getCollection();
    if(relaycollection==null) {
      return null;
    }
    Iterator iter = relaycollection.iterator();
    if(iter==null) {
      return null;
    }
    while(iter.hasNext()) {
      relay=(CmrRelay)iter.next();
      if(relay.getUID().equals(key)) {
        return relay;
      }
    }
    return null;
  }
}
