/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software
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


import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.util.UID;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;

import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.AggQueryResult;
import org.cougaar.core.security.monitoring.blackboard.AggregationDrillDownQuery;
import org.cougaar.core.security.monitoring.blackboard.ConsolidatedEvent;
import org.cougaar.core.security.monitoring.blackboard.DetailsDrillDownQuery;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.AggregatedResponse;
import org.cougaar.core.security.monitoring.blackboard.RemoteConsolidatedEvent;
import org.cougaar.core.security.monitoring.blackboard.DrillDownQuery;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.util.DrillDownUtils;
import org.cougaar.core.security.monitoring.util.DrillDownQueryConstants;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Hashtable;
import java.util.Set;


class AggConsolidatedResponsePredicate implements  UnaryPredicate{
   
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof ConsolidatedEvent ) {
      return true;
    }
    return ret;
  }
}
class DetailsDrillDownPredicate implements  UnaryPredicate{
  private MessageAddress agentAddress;
  public  DetailsDrillDownPredicate(MessageAddress address){
    agentAddress=address;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    CmrRelay cmrRelay=null;
    if (o instanceof CmrRelay ) {
      cmrRelay=(CmrRelay)o;
      if((!(cmrRelay.getSource().equals(agentAddress)))&&
         (cmrRelay.getContent() instanceof DetailsDrillDownQuery)){
        return true;
      }
    }
    return ret;
  }
}

class IdmefAndRemoteEventPredicate implements  UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if(o instanceof Event){
      ret= true;
    }
    if(o instanceof RemoteConsolidatedEvent){
      ret= true;
    }
    return ret;
  }
}

public class MnRAggSendRemoteResponse extends MnRAggQueryBase {
/*
  protected LoggingService loggingService;
  protected MessageAddress myAddress;
*/
  private IncrementalSubscription consolidatedResponse;
  private IncrementalSubscription detailedResponse;
   private IncrementalSubscription idmefEventResponse;
 /* 
 public void setLoggingService(LoggingService ls) {
    loggingService = ls; 
  }
  
  public LoggingService getLoggingService() {
    return loggingService; 
  }
  */

  protected void setupSubscriptions() {
   /* myAddress = getAgentIdentifier();
    if(loggingService == null) {
      loggingService = (LoggingService)
        getServiceBroker().getService(this, LoggingService.class, null); 
    }
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("setupSubscriptions of MnRAggSendRemoteResponse called :"+myAddress.toString() );
    }
    */
     super.setupSubscriptions();
    consolidatedResponse= (IncrementalSubscription)getBlackboardService().subscribe
      (new AggConsolidatedResponsePredicate());
    detailedResponse= (IncrementalSubscription)getBlackboardService().subscribe
      (new DetailsDrillDownPredicate(myAddress));
    idmefEventResponse= (IncrementalSubscription)getBlackboardService().subscribe
      (new IdmefAndRemoteEventPredicate());
  }
  
  protected void execute() {
    Collection responsecol=null;
    if(consolidatedResponse.hasChanged()) {
      responsecol=consolidatedResponse.getAddedCollection();
       if(loggingService.isDebugEnabled()) {
        loggingService.debug("receive consolidated response chnage and size is "+responsecol.size());
      }
      sendAggResponse(responsecol);
    }
    Collection detailscol=null;
    if(detailedResponse.hasChanged()) {
      detailscol=detailedResponse.getAddedCollection();
      processDetailsResponseQuery(detailscol);
    }
    Collection idmefEventCollection=null;
    if(idmefEventResponse.hasChanged()){
       detailscol=idmefEventResponse.getAddedCollection();
      processIdmefEvent(idmefEventCollection);
    }

  }

  public void processIdmefEvent(Collection idmefEventCollection) {
    if(idmefEventCollection==null) {
       if (loggingService.isDebugEnabled()) {
        loggingService.debug("New IDMEF Collection  is NULL  :"+myAddress.toString() );
      } 
      return; 
    }
    if(idmefEventCollection.isEmpty()) {
       if (loggingService.isDebugEnabled()) {
        loggingService.debug("New IDMEF Collection is empty  :"+myAddress.toString() );
      } 
      return; 
    }
    Map map=new Hashtable();
    Iterator iter=idmefEventCollection.iterator();
    Event event=null;
    RemoteConsolidatedEvent remoteEvent=null;
    UID parentUID=null;
    List list=null;
    Object o;
    while(iter.hasNext()){
      o=iter.next();
      if(o instanceof Event) {
        event=(Event)o;
        parentUID=DrillDownUtils.getUID(event.getEvent(),DrillDownQueryConstants.PARENT_UID);
        if(parentUID!=null) {
          if(map.containsKey(parentUID)){
            list=(List)map.get(parentUID);
            list.add(event);
            map.put(parentUID,list);
          }
          else {
            list=new ArrayList();
            list.add(event);
            map.put(parentUID,list);
          }
        }
      }
      if(o instanceof RemoteConsolidatedEvent) {
        remoteEvent=(RemoteConsolidatedEvent)o;
        parentUID=DrillDownUtils.getUID(remoteEvent.getEvent(),DrillDownQueryConstants.PARENT_UID);
        if(parentUID!=null) {
          if(map.containsKey(parentUID)){
            list=(List)map.get(parentUID);
            list.add(createConsolidatedEvent(remoteEvent));
            map.put(parentUID,list);
          }
          else {
            list=new ArrayList();
            list.add(createConsolidatedEvent(remoteEvent));
            map.put(parentUID,list);
          }
        }
      }
    }// end of while
    Collection detailsQueryCollection=getBlackboardService().query(new DetailsDrillDownPredicate(myAddress));
    Set setkeys=map.keySet();
    Iterator keys=setkeys.iterator();
    UID key =null;
    CmrRelay relay=null;
    while(keys.hasNext()){
      list=null;
      key=(UID)keys.next();
      list=(List)map.get(key);
      relay=getCmrRelayWithDetailsDrillDownQuery(key,detailsQueryCollection);
      if(relay==null) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("Canot find Details drill down query relay with parent UID :"+key.toString() );
        } 
        continue;
      }
      AggregatedResponse aggresponse=new AggregatedResponse(list); 
      relay.updateResponse(relay.getSource(),aggresponse);
      getBlackboardService().publishChange(relay);
    }
    
  }

  public CmrRelay getCmrRelayWithDetailsDrillDownQuery(UID parentUID, Collection detailsQueryCollection) {
    CmrRelay relay=null;
    DetailsDrillDownQuery detailsQuery=null;
    if(detailsQueryCollection==null) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("detailsQueryCollection  is NULL  :"+myAddress.toString() );
      } 
      return relay;  
    }
    if(detailsQueryCollection.isEmpty()) {
       if (loggingService.isDebugEnabled()) {
        loggingService.debug("detailsQueryCollection  is NULL  :"+myAddress.toString() );
      } 
       return relay;
    }
    Iterator iter=detailsQueryCollection.iterator();
    while(iter.hasNext()) {
      relay=(CmrRelay)iter.next();
      detailsQuery=(DetailsDrillDownQuery)relay.getContent();
      if(detailsQuery.getParentUID().equals(parentUID)) {
        return relay;
      }
    }
    return relay;
  }
  public void processDetailsResponseQuery(Collection detailscol){
    if(detailscol.isEmpty()){
     if (loggingService.isDebugEnabled()) {
        loggingService.debug("New Detail Query is empty  :"+myAddress.toString() );
      } 
      return; 
    }
    Iterator iter=detailscol.iterator();
    CmrRelay relay=null;
    DetailsDrillDownQuery detailsQuery=null;
    while(iter.hasNext()){
      relay=(CmrRelay)iter.next();
      detailsQuery=(DetailsDrillDownQuery)relay.getContent();
      Collection detailedresponse=getBlackboardService().query(new EventsPredicate(detailsQuery.getParentUID(),myAddress));
      if(detailedresponse.isEmpty()) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug(" No response for DetailsDrillDownQuery  :"+detailsQuery.toString() );
        }
        continue;
      }
      List list=new ArrayList();
      Iterator detailsiter=detailedresponse.iterator();
      while(detailsiter.hasNext()){
        list.add(detailsiter.next());
      }
      AggregatedResponse aggresponse=new AggregatedResponse(list);
      relay.updateResponse(relay.getSource(),aggresponse);
      getBlackboardService().publishChange(relay);
    }
  }
  

  public void sendAggResponse(Collection responsecol) {
    
    if(responsecol.isEmpty()) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("New Consolidate response is empty  :"+myAddress.toString() );
      } 
      return;
    }
    
    Iterator iter=responsecol.iterator();
    CmrRelay relay=null;
    ConsolidatedEvent consolidatedresult=null;
    UID parentuid=null;
    Collection detailsQueryCollection=getBlackboardService().query(new DetailsDrillDownPredicate(myAddress));
    while(iter.hasNext()){
      consolidatedresult=(ConsolidatedEvent)iter.next();
      parentuid=consolidatedresult.getparentUID();
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("Received Consolidated response  received "+ 
                             consolidatedresult.toString()+"\n"+
                             "parent id  "+parentuid );
      }
      relay=getCmrRelayWithDetailsDrillDownQuery(parentuid,detailsQueryCollection);
      List list=new ArrayList();
      list.add(createNewConsolidatedEvent(consolidatedresult));
      AggregatedResponse aggresponse=new AggregatedResponse(list);
      if(relay==null) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("No Details DrillDown query Relay present for parent UID :"+parentuid.toString() );
          loggingService.debug("No Details DrillDown query Relay present looking for Receive agg query relay  :");
        } 
        relay=findCmrRelay(parentuid);
        if(relay!=null) {
          relay.updateResponse(relay.getSource(),aggresponse);
          /*new AggQueryResult(consolidatedresult.getCurrentCount(),
            consolidatedresult.getTotal(),
            consolidatedresult.getRate() ));
          */
          getBlackboardService().publishChange(relay);
          getBlackboardService().publishRemove(consolidatedresult);
          loggingService.debug("Successfully published response to relay :"+relay);
          loggingService.debug("Successfully removed ConsolidatedEvent "+consolidatedresult );
        }
        else {
           loggingService.error("ERROR cannot  find receive Agg relay  :"+ parentuid);
        }
      }
      else {
        loggingService.debug("Since there is a Details Drill down query there is no need to send ConsolidatedEvent "+consolidatedresult );
        /*
        relay.updateResponse(relay.getSource(),aggresponse);
        getBlackboardService().publishChange(relay);
        getBlackboardService().publishRemove(consolidatedresult); 
        */
      }
        
    }
     
  } 
  
  public CmrRelay findCmrRelay(UID key) {
    CmrRelay relay = null;
    final UID fKey = key;
    Collection relays = getBlackboardService().query( new UnaryPredicate() {
        public boolean execute(Object o) {
          if (o instanceof CmrRelay) {
            CmrRelay relay = (CmrRelay)o;
            return ((relay.getUID().equals(fKey)) &&
                    (relay.getContent() instanceof AggregationDrillDownQuery));
          }
          return false;
        }
      });
    if(!relays.isEmpty()) {
      relay = (CmrRelay)relays.iterator().next();
    }
    return relay;
  } 
  public ConsolidatedEvent createNewConsolidatedEvent(ConsolidatedEvent event) {
    ConsolidatedEvent newConsolidateEvent=null;
    CmrFactory factory=null;
    if(domainService!=null) {
      factory=(CmrFactory)domainService.getFactory("cmr");
    } 
    if(factory==null || event==null) {
      return newConsolidateEvent;
    }
    newConsolidateEvent= factory.newConsolidatedEvent(event);
    return newConsolidateEvent;
  }

  public ConsolidatedEvent createConsolidatedEvent(RemoteConsolidatedEvent event) {
    ConsolidatedEvent newConsolidateEvent=null;
    CmrFactory factory=null;
    if(domainService!=null) {
      factory=(CmrFactory)domainService.getFactory("cmr");
    } 
    if(factory==null || event==null) {
      return newConsolidateEvent;
    }
    newConsolidateEvent= factory.newConsolidatedEvent(event);
    return newConsolidateEvent;
  }
}
