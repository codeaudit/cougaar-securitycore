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
import org.cougaar.core.service.community.*;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.multicast.AttributeBasedAddress;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
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
  MessageAddress myAddress;
  public QueryRespondRelayPredicate(MessageAddress myaddress) {
    myAddress = myaddress;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret = ((relay.getSource().equals(myAddress)) &&
          (relay.getContent() instanceof MRAgentLookUp) &&
          (relay.getResponse() instanceof MRAgentLookUpReply)
             );
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


class CapObjPredicate implements UnaryPredicate {
  public boolean execute(Object o) {
    if (o instanceof CapabilitiesObject ) {
      return true;
    }
    return false;
  }
}

public class MnRQueryResponderPlugin extends MnRQueryBase {
  
  private IncrementalSubscription queryResponse;
  private IncrementalSubscription querymapping;
  
  protected void setupSubscriptions() {
  
    super.setupSubscriptions();
    loggingService.debug("setupSubscriptions of MnRQueryResponderPlugin called : "+ myAddress.toString());
    queryResponse= (IncrementalSubscription)getBlackboardService().subscribe(new QueryRespondRelayPredicate(myAddress));
    querymapping= (IncrementalSubscription)getBlackboardService().subscribe(new QueryMappingObjectPredicate());
  }
  
  protected void execute () {
    Collection addedQueryMappingCollection;
    if(querymapping.hasChanged()) {
      addedQueryMappingCollection=querymapping.getAddedCollection();
      if(addedQueryMappingCollection.size()>0) {
        CapabilitiesObject capObj = null;
        Collection capabilitiesCollection =getBlackboardService().query( new CapObjPredicate());
        Iterator i = capabilitiesCollection.iterator();
        // there should only be one capabilities object
        if(i.hasNext()) {
          capObj = (CapabilitiesObject)i.next();
        }
        processLocalQueries(capObj,addedQueryMappingCollection);
      }
    }
    if(queryResponse.hasChanged()) {
      Collection responseCollection;
      responseCollection=queryResponse.getChangedCollection();
      processRemoteQueries(responseCollection);
    }

  }

  private void processLocalQueries(CapabilitiesObject capObj, Collection newMapping) {
    
    Iterator iter=newMapping.iterator();
    CmrRelay relay;
    QueryMapping mapping;
    while(iter.hasNext()) {
      mapping=(QueryMapping)iter.next();
      if(mapping.getRelayUID()!=null) {
        relay=findCmrRelay(mapping.getRelayUID());
        if(relay!=null) {
          if(!relay.getSource().equals(myAddress)){
            processLocalSensors(capObj,relay);
          }
          else {
            loggingService.error("ERROR in mapping or findCmrRelay function");  
          }
        }// end if(relay!=null) 
      }// end if(mapping.getRelayUID()!=null)
    }// end while
    
  }

  
  private void processRemoteQueries(Collection remoteResponse) {
    CmrRelay relay;
    Iterator iter=remoteResponse.iterator();
    Collection queryMapCollection=getBlackboardService().query(new QueryMappingObjectPredicate());
    QueryMapping mapping;
    while(iter.hasNext()) {
      relay=(CmrRelay) iter.next();
      if(relay.getResponse() != null) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug(" Going to look for query mapping object with UID :"+ relay.getUID());
          loggingService.debug(" Source is :"+relay.getSource());
        }
        mapping=findQueryMappingFromBB(relay.getUID(),queryMapCollection);
        if(mapping!=null) {
          ArrayList list=mapping.getQueryList(); 
          OutStandingQuery outstandingquery;
          boolean modified=false;
          if(list!=null) {
            for(int i=0;i<list.size();i++) {
              outstandingquery=(OutStandingQuery)list.get(i);
              loggingService.debug("Ouststanding query uid "+outstandingquery.getUID() + "outstanding object is :"+ outstandingquery.toString());
              if(outstandingquery.getUID().equals(relay.getUID())) {
                loggingService.debug("Receive Response for Ouststanding query uid "+outstandingquery.getUID() + "Current relay id is :"+relay.getUID() );
                outstandingquery.setOutStandingQuery(false);
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
        }// end of sub query list is null
        else{
          loggingService.error("Response is null in processRemoteQueries :" +relay.getUID() );
        }
      }
    }// end while
  }

  private void processLocalSensors(CapabilitiesObject capObj,CmrRelay relay) {
    String key=null;
    RegistrationAlert reg;
    MessageAddress dest_address;
    MRAgentLookUp query;
    if(relay!=null){
      query=(MRAgentLookUp)relay.getContent();
    }
    else{
      loggingService.error("Relay was null in processLocalSensors:");
      return;
    }
    List res= findAgent(query,capObj,true);
    if(res.isEmpty()) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("No Local agents are present with the capabilities. Returning");
      }
      relay.updateResponse(relay.getSource(),new MRAgentLookUpReply(new ArrayList()));
      getBlackboardService().publishChange(relay);
      return;
    }
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("Local agents are present with the capabilities. no of agents are :"+
          res.size());
    }
    Iterator response_iterator=res.iterator();
    ArrayList relay_uid_list=new ArrayList();
    while(response_iterator.hasNext()) {
      key=(String)response_iterator.next();
      //reg=(RegistrationAlert)capabilities.get(key);
      dest_address=MessageAddress.getMessageAddress(key);
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("Adding sensor agent to response :"+ dest_address.toString());
      }
      relay_uid_list.add(dest_address);
    }
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("Update response is being done for source :"+relay.getSource().toString() );
    }
    relay.updateResponse(relay.getSource(),new MRAgentLookUpReply(relay_uid_list));
    loggingService.debug("Update response is being done for relay :"+relay.toString());
    getBlackboardService().publishChange(relay); 
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
            if(reply.getAgentList()!=null) {
              agentList=mergeResponse(agentList, reply.getAgentList());
            }
            else {
              loggingService.debug("list of agents in current relay is null"); 
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
      // there is a possibility that the current relay contains a response
      // if so, we should merge it with the latest response
      MRAgentLookUpReply rr = (MRAgentLookUpReply)relay.getResponse();
      if(rr != null) {
        List l = rr.getAgentList();
        if(l != null) {
          loggingService.debug("Merging agents in the current relay with the subordinate's list of agents");
          agentList = mergeResponse(agentList, l);        
        }
      }
      reply = new MRAgentLookUpReply(agentList);
      map.setResultPublished(true);
      relay.updateResponse(relay.getSource(),reply);
      loggingService.debug("UPDATING RESPONSE AFTER MERGING  "+relay.toString() );
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
}
