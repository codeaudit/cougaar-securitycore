/*
 * <copyright>
 *  Copyright 1997-2003 Networks Associates Technology, Inc.
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
package org.cougaar.core.security.util;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;

import java.util.Collection;
import java.util.Iterator;

/**
 * Utility methods for the CommunityService
 */
public class CommunityServiceUtil {
  private CommunityService _cs;
  private LoggingService _log;
  private ServiceBroker _sb;
  
  public CommunityServiceUtil(ServiceBroker sb) {
    if(sb == null) {
      throw new IllegalArgumentException("ServiceBroker sb is null");
    }
    _sb = sb;
    _cs = (CommunityService)_sb.getService(this, CommunityService.class, null);
    _log = (LoggingService)_sb.getService(this, LoggingService.class, null);
  }

  public void releaseServices() {
    _sb.releaseService(this, CommunityService.class, _cs);
    _sb.releaseService(this, LoggingService.class, _log);
  }
  
  /**
   * determine the m&r security manager for a given entity
   *
   * @param entity the agent or community
   * @return the message address of the m&r security manager
   */
  public MessageAddress findSecurityManager(String entity) {
    MessageAddress myManager = null;
    Iterator c = null;
    String community = null;
    Collection managers = null;
    Collection communities = null;
    
    if(entity == null) {
      throw new IllegalArgumentException("String entity is null");
    }
    
    communities = _cs.listParentCommunities(entity, "(CommunityType=Security)");    
    // base case
    if(communities == null || communities.isEmpty()) {
      return null;
    }
    
    c = communities.iterator();
    while(c.hasNext()) {
      community = (String)c.next();
      _log.debug("searching for a security manager in community('" + community + "')");
      managers = _cs.searchByRole(community, "Manager");
      // ensure manager exist and manager is not the current entity
      if(!managers.isEmpty()) {
        // should only have one manager per component
        Iterator m = managers.iterator();
        MessageAddress manager = null;
        while(m.hasNext()) {
          myManager = (MessageAddress)m.next();
          if(!entity.equals(myManager.toString())) {
            // found a manager in this community
            return myManager;
          }
        }
      }

      // try to find the manager in the community's parent communities since
      // communities can be nested and can be members of other communities
      _log.debug("searching for security manager in community('" + community + "') parent communities");
      // need to traverse the community hierarchy
      myManager = findSecurityManager(community);
      if(myManager != null) {
        return myManager; 
      }
    } // while(e.hasNext())
    // no security manager for this agent or community
    return null;
  }
  
  public String getSecurityCommunity(String agent) {
    String myCommunity = null;
    Collection communities = _cs.listParentCommunities(agent, "(CommunityType=Security)");
    if(!communities.isEmpty()) {
      if(communities.size() == 1) {
        myCommunity = (String)communities.iterator().next();  
      }
      else {
        _log.debug("multiple security communities for " + agent);  
        Iterator c = communities.iterator();
        Collection members = null;
        while(c.hasNext()) {
          String community = (String)c.next();
          Collection roles = _cs.getEntityRoles(community, agent);
          if(!roles.isEmpty() && roles.contains("Manager")) {
            myCommunity = community;
            break;   
          }
        }
      }
    }
    else {
       _log.error(agent + " does not belong to any security community"); 
    }
    _log.debug("returning security community '" + myCommunity + "'");
    return myCommunity;
  }

  public boolean amIRoot(String agent) {
    Collection roles = _cs.getEntityRoles(getSecurityCommunity(agent), agent);
    return (roles.contains("Root") || roles.contains("root"));
  }
}
