/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
import org.cougaar.core.util.UID;
import org.cougaar.core.service.community.*;

//Security services
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;
import org.cougaar.core.security.util.CommunityServiceUtil;

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

class NewQueryRelayPredicate implements  UnaryPredicate{
  MessageAddress myAddress;
  public NewQueryRelayPredicate(MessageAddress myaddress) {
    myAddress = myaddress;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret = ((!relay.getSource().equals(myAddress)) &&(
                 (relay.getContent() instanceof MRAgentLookUp) &&
                 (relay.getResponse()==null)));
    }
    return ret;
  }
}

class RemoteQueryRelayPredicate implements  UnaryPredicate{
  MessageAddress myAddress;
  
  public RemoteQueryRelayPredicate(MessageAddress myaddress) {
    myAddress = myaddress;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret = ((!relay.getSource().equals(myAddress))&&
          (relay.getContent() instanceof MRAgentLookUp)
             ) ;
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

public class MnRQueryReceiverPlugin extends MnRQueryBase {

  // The domainService acts as a provider of domain factory services
  private IncrementalSubscription capabilitiesobject;
  private IncrementalSubscription newQueryRelays;
  private IncrementalSubscription remoteQueryRelays;
  private CapabilitiesObject      _capabilities;
  
  // private String param;
  private boolean root = false;
  private String myRole = null;
  
  public void setParameter(Object o){
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
          "instead of " + 
          ( (o == null)
              ? "null" 
              : o.getClass().getName() ));
    }

    List l = (List) o;
    Iterator iter = l.iterator();
    String param=null; ;
    param = (String)iter.next();
    if(param.equalsIgnoreCase("root")){
      root = true;
    }
  }
  
  protected void setupSubscriptions() {
    
    super.setupSubscriptions();    
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("setupSubscriptions of MnRQueryReceiverPlugin " +
                           "called :" + myAddress);
    }
    
    capabilitiesobject= (IncrementalSubscription)
      getBlackboardService().subscribe(new CapabilitiesObjectPredicate());

    newQueryRelays =(IncrementalSubscription) getBlackboardService().
      subscribe(new NewQueryRelayPredicate(myAddress));

    remoteQueryRelays = (IncrementalSubscription)getBlackboardService().
      subscribe(new RemoteQueryRelayPredicate(myAddress));

    if (loggingService.isDebugEnabled()) {
      if (amIRoot()) {
        loggingService.debug("security community set as ROOT");
      }
    }
  }
 
  protected synchronized void execute () {
    loggingService.debug(myAddress + " execute().....");
    CapabilitiesObject capabilities=null;
    Collection capabilitiesCollection;
    Collection newQueryCollection;
    Collection removedRemoteQueryCol;
    boolean removedRelays=false;
    
    if (remoteQueryRelays == null) {
      // Configuration problem. Did not go through setupSubscription.
      // Issue should have already reported during setupSubscription()
      return;
    }

    if(remoteQueryRelays.hasChanged()) {
      removedRemoteQueryCol=remoteQueryRelays.getRemovedCollection();
      if(removedRemoteQueryCol.size()>0) {
        loggingService.debug(" REMOTE RELAY REMOVED SIZE  ----"+removedRemoteQueryCol.size() );
        removedRelays=true;
        removeRelays(removedRemoteQueryCol);
      }
    }
    if(capabilitiesobject.hasChanged()) {
      loggingService.debug(" Capabilities HAS CHANGED ----");
      capabilitiesCollection=capabilitiesobject.getChangedCollection();
      if (!capabilitiesCollection.isEmpty()) {
        if (!isRootReady()) {
          // store it for later...
          if (!capabilitiesCollection.isEmpty()) {
            _capabilities = (CapabilitiesObject)
              capabilitiesCollection.iterator().next();
            return;
          }
        } else {
          if (_capabilities != null) {
            if (amIRoot()) {
              processPersistantQueries(_capabilities);
            }
            _capabilities = null;
          }
          if(amIRoot()) {
            capabilities = (CapabilitiesObject)
              capabilitiesCollection.iterator().next();
            processPersistantQueries(capabilities);
            return;
          }
        }
      }
    } else {
      capabilitiesCollection=capabilitiesobject.getCollection();
      Iterator i=capabilitiesCollection.iterator();
      if(i.hasNext()) {
        capabilities=(CapabilitiesObject) i.next();
      }
    }

    if(newQueryRelays.hasChanged()){
      loggingService.debug(" newqueryRelays HAS CHANGED ----");
      newQueryCollection=newQueryRelays.getAddedCollection();
      processNewQueries(capabilities,newQueryCollection);
    }
     
  }

  private void processPersistantQueries(final
                                        CapabilitiesObject capabilities) {
    QueryMapping mapping;
    MRAgentLookUp agentlookupquery;
    CmrRelay relay;
    Collection remoteRelays=getBlackboardService().query(new RemoteQueryRelayPredicate(myAddress));
    if(remoteRelays.size()<1) {
      loggingService.debug("Empty remote relays");
      return;
    }
    else {
      loggingService.debug("Size of  remote relays"+remoteRelays.size() );
    }
    
    Collection queryMappingCollection=getBlackboardService().query(new QueryMappingPredicate());
    Iterator iter=remoteRelays.iterator();
    // removing mapping for remote relay 
    while(iter.hasNext()){
      mapping=null;
      relay = (CmrRelay)iter.next();
      agentlookupquery=(MRAgentLookUp)relay.getContent();
      if(agentlookupquery==null) {
        loggingService.warn("Contents of the relay is null:"+relay.toString());
        continue;
      }
      mapping=findQueryMappingFromBB(relay.getUID(),queryMappingCollection) ;
      if(mapping!=null) {
        loggingService.debug("REMOVING OLD MAPPING"+mapping.toString());
        removeRelay(mapping);
        getBlackboardService().publishRemove(mapping);
      }
    }
    // publish new mapping for relays 
    iter=remoteRelays.iterator();
    while(iter.hasNext()) {
      mapping=null;
      relay = (CmrRelay)iter.next();
      agentlookupquery=(MRAgentLookUp)relay.getContent();
      if(agentlookupquery==null) {
        loggingService.warn("Contents of the relay is null:"+relay.toString());
        continue;
      }
      if(agentlookupquery.updates) {
        final CmrRelay fRelay = relay;
        mapping=findQueryMappingFromBB(relay.getUID(),queryMappingCollection) ;
        FindAgentCallback fac = new FindAgentCallback() {
            public void execute(Collection agents) {
              if (loggingService.isDebugEnabled()) {
                loggingService.debug("Found response for manager and size " +
                                     "of response :" + agents.size() );
              }
              createSubQuery(capabilities, agents, fRelay);
            }
          };
        findAgent(agentlookupquery, capabilities, false, fac);
      }// end agentlookupquery.updates
    }//end while()
  }  

  private void processNewQueries(final CapabilitiesObject capabilities, 
                                 final Collection newQueries) {
    QueryMapping mapping;
    Iterator iter=newQueries.iterator();
    MRAgentLookUp agentlookupquery;
    Collection queryMappingCollection=getBlackboardService().query(new QueryMappingPredicate());
    while(iter.hasNext()) {
      mapping=null;
      final CmrRelay relay = (CmrRelay)iter.next();
      agentlookupquery=(MRAgentLookUp)relay.getContent();
      if(agentlookupquery==null) {
        loggingService.warn("Contents of the relay is null:"+relay.toString());
        continue;
      }
      mapping=findQueryMappingFromBB(relay.getUID(),queryMappingCollection) ;
      if(mapping==null) {
        FindAgentCallback fac = new FindAgentCallback() {
            public void execute(Collection agents) {
              if (loggingService.isDebugEnabled()) {
                loggingService.debug("Found response for manager and size " +
                                     "of response :" + agents.size() );
              }
              createSubQuery(capabilities, agents, relay);
            }
          };
        findAgent(agentlookupquery, capabilities, false, fac);
      }
      else {
        loggingService.error(" There should have been No Mapping object for :"+relay.getUID());
      }
    }// end of While
  }// end  processNewQueries
  

  private void createSubQuery(CapabilitiesObject capabilities, 
                              Collection subManager, CmrRelay relay) {
    QueryMapping mapping;
    MRAgentLookUp agentlookupquery=null;
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    if(relay!=null) {
      agentlookupquery=(MRAgentLookUp)relay.getContent();
    }
    else {
      loggingService.error("relay is null in createSub query ");
    }
    if(!subManager.isEmpty()) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("MnRQueryReceiver plugin  Creating new Sub Query relays:"
            + myAddress.toString());
      }
      Iterator response_iterator=subManager.iterator();
      String key=null;
      RegistrationAlert reg;
      MessageAddress dest_address;
      ArrayList relay_uid_list=new ArrayList();
      //boolean modified=false;
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("Going through list of agents found in Query receiver plugin  :");
      }
      while(response_iterator.hasNext()) {
        key=(String)response_iterator.next();
        reg=(RegistrationAlert)capabilities.get(key);
        dest_address=MessageAddress.getMessageAddress(key);
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("Creators Address for Sub Query relay is :"
              + myAddress.toString());
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
      }
      mapping=new QueryMapping(relay.getUID(), relay_uid_list);
      getBlackboardService().publishAdd(mapping);
    }
    else {
      loggingService.debug(" No sub Manager are present with this capabilities :");
      loggingService.debug("Creating an empty query mapping  :");
      mapping=new QueryMapping(relay.getUID(), null);
      getBlackboardService().publishAdd(mapping);
    }
  }


  private void removeRelays(Collection removedRelays) {
    CmrRelay relay;
    QueryMapping mapping;
    Iterator iter=removedRelays.iterator();
    Collection queryMappingCollection=getBlackboardService().query(new QueryMappingPredicate());
    loggingService.debug("SIZE OF queryMappingCollection:"+queryMappingCollection.size());
    while(iter.hasNext()) {
      mapping=null;
      relay = (CmrRelay)iter.next();
      mapping=findQueryMappingFromBB(relay.getUID(),queryMappingCollection) ;
      if(mapping!=null) {
        loggingService.debug("REMOVING MAPPING :"+mapping.toString());
        removeRelay(mapping);
      }
      else {
        loggingService.debug("REMOVING MAPPING COULD not find mapping for Relay :"+relay.getUID());
      }
    }// end while
  }// end removeRelays

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
  
  /*
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
  */

  private class AllMyRelayPredicate implements UnaryPredicate {
    public boolean execute(Object o) {
      boolean ret = false;
      if (o instanceof CmrRelay ) {
        CmrRelay relay = (CmrRelay)o;
        ret = ( (relay.getSource().equals(myAddress))&&
            (relay.getContent() instanceof MRAgentLookUp));
      }
      return ret;
    }
  }
}
