/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software Inc.
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



//Cougaar core  
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.*;
import org.cougaar.core.service.community.*;
import org.cougaar.core.security.util.CommunityServiceUtil;

import org.cougaar.core.util.UID;

//Security services
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;

import java.util.Collection;
import java.util.ArrayList;
import java.util.Iterator;



class AggQueryMappingPredicate implements UnaryPredicate {

  public boolean execute(Object o) {
    if( o instanceof AggQueryMapping){
      return true;
    }
    return false;
  }
  
}



public abstract class MnRAggQueryBase extends ComponentPlugin {
  
  protected LoggingService loggingService;
  protected CommunityService communityService;
  protected DomainService domainService;
  protected MessageAddress myAddress;
  protected CommunityServiceUtil _csu;
  private boolean _isRoot = false;
  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService ds) {
    domainService = ds;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
  }
  
  /**
   * Used by the binding utility through reflection to set my CommunityService
   */
  public void setCommunityService(CommunityService cs) {
    communityService = cs;
  }

  /**
   * Used by the binding utility through reflection to get my CommunityService
   */
  public CommunityService getCommunityService() {
    return communityService;
  }
  
  public void setLoggingService(LoggingService ls) {
    loggingService = ls; 
  }
  
  public LoggingService getLoggingService() {
    return loggingService; 
  }


  protected void setupSubscriptions() {
    
    myAddress = getAgentIdentifier();
    if(loggingService == null) {
      loggingService = (LoggingService)
        getServiceBroker().getService(this, LoggingService.class, null); 
    }
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("setupSubscriptions of MnRAggResponseAggregator called :"
                           + myAddress.toString());
    }
    _csu = new CommunityServiceUtil(getServiceBroker());
    _isRoot = _csu.amIRoot(myAddress.toString());
   
  }
  
  protected boolean amIRoot() {
    return _isRoot;
  } 
  
  protected AggQueryMapping findAggQueryMappingFromBB(UID givenUID, Collection aggQueryMappingCol ) {
    AggQueryMapping aggQuerymapping=null;
    ArrayList queryList=null;;
    AggQueryResult result=null;
    
    if(aggQueryMappingCol.isEmpty()) {
      return aggQuerymapping;
    }
    Iterator iter=aggQueryMappingCol.iterator();
    while(iter.hasNext()) {
      aggQuerymapping=(AggQueryMapping)iter.next();
      synchronized(aggQuerymapping){
        if(aggQuerymapping.getParentQueryUID().equals(givenUID)){
          return aggQuerymapping;
        }
        else {
          queryList=aggQuerymapping.getQueryList();
          if(queryList==null) {
            continue;
          }
          for(int i=0;i<queryList.size();i++) {
            result=(AggQueryResult)queryList.get(i);
            if(result.getUID().equals(givenUID)) {
              return aggQuerymapping;
            }
          }// end of for
        }// end else
      }
    }//end of while
    return null;
  } 
  
  protected Object findObject(UID uid) {
    Object queryObject = null;
    final UID fKey = uid;
    Collection relays = getBlackboardService().query( new UnaryPredicate() {
        public boolean execute(Object o) {
          SensorAggregationDrillDownQuery  sensorquery=null;
          if ((o instanceof CmrRelay)||( o instanceof SensorAggregationDrillDownQuery))  {
            if(o instanceof CmrRelay) {
              CmrRelay relay = (CmrRelay)o;
              return ((relay.getUID().equals(fKey)) &&
                      (relay.getContent() instanceof DrillDownQuery ));
            }
            if( o instanceof SensorAggregationDrillDownQuery) {
              sensorquery=(SensorAggregationDrillDownQuery)o;
              return(sensorquery.getUID().equals(fKey));
            }
          }
          return false;
        }
      });
    if(!relays.isEmpty()) {
      queryObject = relays.iterator().next();
    }
    return queryObject;
    
  } 
   
}
