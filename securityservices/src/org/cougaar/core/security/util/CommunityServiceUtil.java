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
package org.cougaar.core.security.util;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.Entity;
import org.cougaar.core.service.community.CommunityChangeListener;
import org.cougaar.core.service.community.CommunityChangeEvent;

import EDU.oswego.cs.dl.util.concurrent.Semaphore;

import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import javax.naming.directory.*;
import javax.naming.*;

/**
 * Utility methods for the CommunityService
 */
public class CommunityServiceUtil {
  private CommunityService _cs;
  private LoggingService _log;
  private ServiceBroker _sb;
  private boolean isMnRManager=false;
 
  
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
   * Number of seconds to wait until we check whether we have
   * a response from the community service. It's hard to know
   * when we should have a response. This value is used only
   * to help with debugging, e.g. if we timeout, then we dump
   * a warning in the logger.
   */
  public static final long COMMUNITY_WARNING_TIMEOUT = 300 * 1000;

  public static final String SECURITY_COMMUNITY_TYPE = "Security";
  private static final String MANAGER_ROLE = "Manager";
  private static final String MANAGER_ROOT = "Root";
  private static final String MEMBER_ROLE = "Member";
  private static final String ROLE_FILTER = "(Role=" + MANAGER_ROLE +")";
  private static final String ROLE_MEMBER_FILTER = "(Role=" + MEMBER_ROLE +")";
  private static final String ROOT_FILTER = "(&(Role=" + MANAGER_ROLE +")" +
  "(Role=" + MANAGER_ROOT + "))";

  /**
   * determine the m&r security managers for a given entity
   *
   * @param entity the agent or community
   * @return the message address of the m&r security manager
   */
  public void findSecurityManager(final String entity,
				  final CommunityServiceUtilListener listener) {
    //MessageAddress myManager = null;
    //Iterator c = null;
    //String community = null;
    //Collection managers = null;
    //Collection communities = null;
    if(_log.isDebugEnabled()){
      _log.debug("Creating a CommunityResponseListener in community"+entity );
    }
    CommunityResponseListener crl = new CommunityResponseListener() {
	public void getResponse(CommunityResponse resp) {
	  Object response = resp.getContent();
	  if (!(response instanceof Set)) {
	    String errorString = "Unexpected community response class:"
	      + response.getClass().getName() + " - Should be a Set";
	    _log.error(errorString);
	    throw new RuntimeException(errorString);
	  }
          if(_log.isDebugEnabled()){
            _log.debug("Going to set response in community listner of Sensor Plugin"+entity);
          }
	  Set set = (Set) response;
          if (!set.isEmpty()) {
            listener.getResponse(set);
          } else {
            // wait for one to be there...
            if (_log.isDebugEnabled()) {
              _log.debug("Waiting for security manager to be available..." + entity);
              _log.debug("Waiting for security manager to be available... Adding GetSecurityManager listener " + entity);
            }
            _cs.addListener(new GetSecurityManager(listener,entity));
          }
	}
      };

    String filter = "(& (CommunityType=" + SECURITY_COMMUNITY_TYPE
      + ") (Role=" + MANAGER_ROLE +") )";
    Collection agents = 
      _cs.searchCommunity(null, filter, true, Community.AGENTS_ONLY, crl);
    if (agents != null) {
      listener.getResponse((Set) agents);
    }
  }

  private boolean isManagedCommunity(Community community, String agent) {
    if (_log.isDebugEnabled()) {
      _log.debug(" doing a community search in isManagedCommunity with Role=manager and agents only" +community.getName() +
                 "   For agent : " + agent );
    }
    Set agents = community.search(ROLE_FILTER, Community.AGENTS_ONLY);
    if (_log.isDebugEnabled()) {
      _log.debug("Got response for  .. search in isManagedCommunity with Role=manager and agents only" +community.getName() +
                 "   For agent : " + agent + " Response is : "+agents);
    }
    Iterator jter = agents.iterator();
    while (jter.hasNext()) {
      Entity entity = (Entity) jter.next();
      if (entity.getName().equals(agent)) {
        if (_log.isDebugEnabled()) {
          _log.debug(" In isManagedCommunity  Found community where role is Manager :" +community.getName());
        }
        // found one where the role is manager
        return true;
      }
    }
    return false;
  }

  private Community getManagedCommunity(Collection communities, String agent) {
    if (_log.isDebugEnabled()) {
      _log.debug("getManagedCommunity called with communities : "+communities +"   For Agent :  "+ agent); 
    }
    Iterator iter = communities.iterator();
    while (iter.hasNext()) {
      Community community = (Community) iter.next();
      if (isManagedCommunity(community, agent)) {
        // found one where the role is manager
        if (_log.isDebugEnabled()) {
          _log.debug(" In get Managed Community returning community name with role=manager : "+ community.getName());
        }
        return community;
      }
    }
    return null; // none of them
  }


  private void isAgentMnRManager(Collection  communities, String agent) {
    Iterator iter = communities.iterator();
    while (iter.hasNext()) {
      Community community = (Community) iter.next();
      Set agents = community.search(ROLE_FILTER, Community.AGENTS_ONLY);
      if (_log.isDebugEnabled()) {
        _log.debug("Got response for  .. search in isAgentMnRManager(Collection communities) "+
                   "with Role=manager and agents only" +community.getName() +
                   "  For agent : " + agent + " Response is : "+agents);
      }
      Iterator jter = agents.iterator();
      while (jter.hasNext()) {
        Entity entity = (Entity) jter.next();
        if (entity.getName().equals(agent)) {
          isMnRManager= true;
        }
      }
    }
  }

  private void isAgentMnRManager(Community community, String agent) {
    if(community==null || agent==null) {
      return ;
    }
    
    Set agents = community.search(ROLE_FILTER, Community.AGENTS_ONLY);
    if (_log.isDebugEnabled()) {
      _log.debug("Got response for  .. search in isAgentMnRManager(Community)"+
                 " with Role=manager and agents only" +community.getName() +
                 "   For agent : " + agent + " Response is : "+agents);
    }
    Iterator jter = agents.iterator();
    while (jter.hasNext()) {
      Entity entity = (Entity) jter.next();
      if(entity.getName().equals(agent)) {
        isMnRManager= true;
      }
    }
  }

  public boolean isRoot(Community community) {
    Set set = community.search(ROOT_FILTER, Community.AGENTS_ONLY);
    return !set.isEmpty();
  }

  public void getSecurityCommunity(final String agent,
                                   final CommunityServiceUtilListener listener) {
    if (_log.isDebugEnabled()) {
      _log.debug("Find security community for " + agent);
    }

    CommunityResponseListener crl = new CommunityResponseListener() {
	public void getResponse(CommunityResponse resp) {
	  Object response = resp.getContent();
          if (_log.isDebugEnabled()) {
            _log.debug("CommunityResponseListener called .....................");
            _log.debug("CommunityResponseListener called getSecurityCommunity (agent, CommunityServiceUtilListener) " + agent);
          }

	  if (!(response instanceof Set)) {
	    String errorString = "Unexpected community response class:"
	      + response.getClass().getName() + " - Should be a Set";
	    _log.error(errorString);
	    throw new RuntimeException(errorString);
	  }
          Set set = (Set) response;
          if (_log.isDebugEnabled()) {
            _log.debug("Calling  getManagedCommunity(set,agent) from crl "+set +" agent : "+  agent);
          }
          Community mine = getManagedCommunity(set, agent);
          if (mine != null) {
            if (_log.isDebugEnabled()) {
              _log.debug("Collection mine is not Null after  getManagedCommunity(set,agent)"+ mine);
            }
            listener.getResponse(Collections.singleton(mine));
            return;
          }
          if(_log.isDebugEnabled()) {
            _log.debug("Collection mine is Null ADDING after  GetManagedCommunity LISTENER ");
          }
          // didn't find any appropriate community... start a listener
          _cs.addListener(new GetManagedCommunity(agent, listener));
	}
      };
    String filter = "(CommunityType=" + SECURITY_COMMUNITY_TYPE + ")";
    Collection communities = 
      _cs.searchCommunity(null, filter, true, Community.COMMUNITIES_ONLY, crl);
    if (_log.isDebugEnabled()) {
      _log.debug("DOING SEARCH WITH COMMUNITIES ONLY IN getSecurityCommunity " + agent );
    }
    if (communities != null) {
      if (_log.isDebugEnabled()) {
        _log.debug(" SEARCH WITH COMMUNITIES RETURNED NON null Collection  ");
        _log.debug(" Calling getManagedCommunity(set,agent) from getSecurityCommunity" );
      }
      isAgentMnRManager(communities, agent);
      Community mine = getManagedCommunity(communities, agent);
      if (mine != null) {
        listener.getResponse(Collections.singleton(mine));
        return;
      }
      // didn't find any appropriate community... start a listener
      _cs.addListener(new GetManagedCommunity(agent, listener));
    }
    else {
      if (_log.isDebugEnabled()) {
        _log.debug(" SEARCH WITH COMMUNITIES RETURNED null Collection " + agent);
        _log.debug("Waiting for CALLBACK ....................");
      }
    }
  }

  public Community getSecurityCommunity(String agent) {
    Community myCommunity = null;
    if (_log.isDebugEnabled()) {
      _log.debug("Find security community for " + agent);
    }

    final Status status = new Status();
    final Semaphore s = new Semaphore(0);
    CommunityResponseListener crl = new CommunityResponseListener() {
	public void getResponse(CommunityResponse resp) {
	  Object response = resp.getContent();
	  if (!(response instanceof Set)) {
	    String errorString = "Unexpected community response class:"
	      + response.getClass().getName() + " - Should be a Set";
	    _log.error(errorString);
	    throw new RuntimeException(errorString);
	  }
	  status.value = response;
	  s.release();
	}
      };
    // TODO: do this truly asynchronously.
    String filter = "(CommunityType=" + SECURITY_COMMUNITY_TYPE + ")";
    Collection communities = 
      _cs.searchCommunity(null, filter, true, Community.COMMUNITIES_ONLY, crl);

    if (communities == null) {
      try {
        s.acquire();
        communities = (Set) status.value;
      } catch (InterruptedException ie) {
        _log.error("Error in searchByCommunity:", ie);
      }
    }

    Iterator it = communities.iterator();
    filter = "(Role=" + MANAGER_ROLE +")";
    while(it.hasNext() && myCommunity != null) {
      Community community = (Community)it.next();
      Set entities = community.search(filter, Community.AGENTS_ONLY);
      Iterator it2 = entities.iterator();
      while (it2.hasNext()) {
        Entity ent = (Entity)it2.next();
        if (agent.equals(ent.getName())) {
          myCommunity = community;
          break;
        }
      }
    }
    if (myCommunity == null) {
      if (_log.isDebugEnabled()) {
        _log.debug(agent + " is not manager of any security community. " +
                   "Waiting..."); 
      }
      try {
        GetSecurityCommunity listener = new GetSecurityCommunity(s, agent);
        _cs.addListener(listener);
        s.acquire();
        _cs.removeListener(listener);
        myCommunity = listener.getCommunity();
      } catch (InterruptedException ie) {
        _log.error("Error in listening:", ie);
      }
    }
    if (_log.isDebugEnabled()) {
      _log.debug(agent + " is manager of community " + myCommunity);
    }
    return myCommunity;
  }

  public boolean amIRoot(String agent) {
    Community myCommunity = getSecurityCommunity(agent);
    String role = "Root";
    String filter = "(Role=" + role +")";
    if (myCommunity == null) {
      if (_log.isWarnEnabled()) {
	_log.warn(agent + " is not part of any security community");
      }
      return false;
    }
    Set entities = myCommunity.search(filter, Community.AGENTS_ONLY);
    Iterator it = entities.iterator();
    while (it.hasNext()) {
      Entity entity = (Entity) it.next();
      if (entity.getName().equals(agent)) {
	return true;
      }
    }
    return false;
  }

  public boolean containsEntity(Set set, String agent) {
    boolean contains=false;
    if(set==null) { 
      if (_log.isDebugEnabled()) {
        _log.debug( "returning as set is NULL");
      }
      return contains;
    }
    if(set.isEmpty()) {
      if (_log.isDebugEnabled()) {
        _log.debug( "returning as set is EMPTY");
      }
      return contains;
    }
    Iterator iter=set.iterator();
    Entity entity=null;
    while(iter.hasNext()){
      entity=(Entity)iter.next();
      if (_log.isDebugEnabled()) {
        _log.debug( "comparing : "+ entity.getName() + " with "+ agent);
      }
      if(entity.getName().trim().equals(agent)) {
        if (_log.isDebugEnabled()) {
          _log.debug(" Found : "+ entity.getName().trim() + " EQUALS" + agent);
        }
        contains=true;
        return contains; 
      }
    }
    return contains;
  }

  /*
    public Collection getParentSecurityCommunities(String agent) {
    _log.debug("Find security community for " + agent);

    final Status status = new Status();
    final Semaphore s = new Semaphore(0);
    CommunityResponseListener crl = new CommunityResponseListener() {
    public void getResponse(CommunityResponse resp) {
    Object response = resp.getContent();
    if (!(response instanceof Set)) {
    String errorString = "Unexpected community response class:"
    + response.getClass().getName() + " - Should be a Set";
    _log.error(errorString);
    throw new RuntimeException(errorString);
    }
    status.value = response;
    s.release();
    }
    };
    // TODO: do this truly asynchronously.
    String filter = "(CommunityType=" + SECURITY_COMMUNITY_TYPE + ")";
    Collection communities = 
    _cs.searchCommunity(null, filter, true, Community.COMMUNITIES_ONLY, crl);

    if (communities == null) {
    try {
    s.acquire();
    communities = (Set) status.value;
    } catch (InterruptedException ie) {
    _log.error("Error in searchByCommunity:", ie);
    }
    }

    if(communities.isEmpty()) {
    _log.debug(agent + " does not belong to any security community... yet. Waiting..."); 
    try {
    GetSecurityCommunity listener = new GetSecurityCommunity(s);
    _cs.addListener(listener);
    s.acquire();
    _cs.removeListener(listener);
    communities = Collections.singleton(listener.getCommunity());
    if (_log.isDebugEnabled()) {
    _log.debug(agent + " belongs to community " + 
    listener.getCommunity()); 
    }
    } catch (InterruptedException ie) {
    _log.error("Error in listening:", ie);
    }
    }
    return communities;
    } 
  */

  private class Status {
    public Object value;
  }

  private static boolean isSecurityCommunity(Community community) {
    try {
      Attributes attrs = community.getAttributes();
      Attribute attr = attrs.get("CommunityType");
      if (attr == null) {
        return false;
      }
      for (int i = 0; i < attr.size(); i++) {
        Object type = attr.get(i);
        if (type.equals("Security")) {
          return true;
        }
      }
      return false;
    } catch (NamingException e) {
      throw new RuntimeException("This should never happen");
    }
  }

  private class GetSecurityCommunity implements CommunityChangeListener {
    private Community _member;
    private Semaphore _semaphore;
    private String    _agent;

    public GetSecurityCommunity(Semaphore s, String agent) {
      _semaphore = s;
      _agent = agent;
    }

    public void communityChanged(CommunityChangeEvent event) {
      Community community = event.getCommunity();
      if (_log.isDebugEnabled()) {
        _log.debug("community change: " + 
                   event.getChangeTypeAsString(event.getType()) +
                   ", " +
                   event.getWhatChanged());
      }
      if (!isSecurityCommunity(community)) {
        if (_log.isDebugEnabled()) {
          _log.debug("not a security community: " + community.getName());
        }
        return;
      }
      if (_log.isDebugEnabled()) {
        _log.debug("examining security community: " + community.getName());
      }
      isAgentMnRManager(community,_agent);
      
      Set set =  set= community.search(ROLE_FILTER, Community.AGENTS_ONLY);
      Iterator iter = set.iterator();
      while (iter.hasNext()) {
        Entity agent = (Entity) iter.next();
        if (_log.isDebugEnabled()) {
          _log.debug("Managing agent = " + agent.getName());
        }
        if (agent.getName().equals(_agent)) {
          _member = community;
          _semaphore.release();
          if (_log.isDebugEnabled()) {
            _log.debug("found security community: " + community.getName());
          }
          return;
        }
      }
      if (_log.isDebugEnabled()) {
        _log.debug(_agent + " is not any of the managers");
      }
    }

    public String getCommunityName() {
      return null; // all MY communities
    }

    public Community getCommunity() {
      return _member;
    }
  };

  private class GetSecurityManager  implements CommunityChangeListener {
    private CommunityServiceUtilListener _listener;
    private String entity;
    public GetSecurityManager(CommunityServiceUtilListener listener, String Entity ) {
      _listener = listener;
      entity=Entity;
    }

    public void communityChanged(CommunityChangeEvent event) {
      if (_log.isDebugEnabled()) {
        _log.debug("GetSecurityManager Listener called :");
      }
      Community community = event.getCommunity();
      if (!isSecurityCommunity(community)) {
        if (_log.isDebugEnabled()) {
          _log.debug("not a security community: " + community.getName() + "For Entity :"+ entity);
        }
        return;
      }
      if (_log.isDebugEnabled()) {
        _log.debug("examining security community: " + community.getName()+ "For Entity :"+ entity);
      }
      Set set=null;
      if(isMnRManager){
        set = community.search(ROLE_MEMBER_FILTER, Community.AGENTS_ONLY);
        Set mgrset= community.search(ROLE_FILTER, Community.AGENTS_ONLY);
        boolean member =containsEntity(set,entity);
        boolean mgr=containsEntity(mgrset,entity);
        if(member && mgr) {
          if (_log.isDebugEnabled()) {
            _log.debug("GetSecurityManager Listener returning as it is member + mgr in community : "+ community.getName());
            _log.debug("GetSecurityManager Listener Done ..................... :");
          }
          return;
        }
        if (_log.isDebugEnabled()) {
          _log.debug("Search for member returned : "+ set);
        }
        if(containsEntity(set,entity)){
          if (_log.isDebugEnabled()) {
            _log.debug("Found Manager for entity : "+ entity + " Manager  : "+set);
          }
          set = community.search(ROLE_FILTER, Community.AGENTS_ONLY);
          
        }
        else{
          if (_log.isDebugEnabled()) {
            _log.debug("Entity is not member any where : "+ entity + " Manager  : "+set);
          }
          set=null;
        }
      }
      else {
        set = community.search(ROLE_FILTER, Community.AGENTS_ONLY);
      }
      if (set != null && !set.isEmpty()) {
        _cs.removeListener(this);
        _listener.getResponse(set);
        if (_log.isDebugEnabled()) {
          _log.debug("Security manager found: " + set + "For Entity :"+ entity);
        }
      } else {
        if (_log.isDebugEnabled()) {
          _log.debug("Security community does not have manager yet: " +
                     community.getName()+ "For Entity :"+ entity );
        }
      }
      if (_log.isDebugEnabled()) {
        _log.debug("GetSecurityManager Listener Done ..................... :");
      }
    }
    public String getCommunityName() {
      return null; // all MY communities
    }
  };

  private class GetManagedCommunity
  implements CommunityChangeListener {
    private CommunityServiceUtilListener _listener;
    private String                       _agent;

    public GetManagedCommunity(String agent,
                               CommunityServiceUtilListener listener) {
      _listener = listener;
      _agent = agent;
    }

    public void communityChanged(CommunityChangeEvent event) {
      if (_log.isDebugEnabled()) {
        _log.debug("GetManagedCommunity Listener Called..................... :");
      }
      Community community = event.getCommunity();
      if (!isSecurityCommunity(community)) {
        if (_log.isDebugEnabled()) {
          _log.debug("not a security community: " + community.getName()+ "  For agent : "+_agent );
          _log.debug("GetManagedCommunity Listener Done..................... :");
        }
        return;
      }
      if (_log.isDebugEnabled()) {
        _log.debug("examining security community: " + community.getName()+ "  For agent : "+_agent);
        Collection entites=community.getEntities();
        Iterator iter=entites.iterator();
        Entity entity =null;
        _log.debug("Printing all entities and their attributes for community : "+ community.getName());
        while(iter.hasNext()){
          entity=(Entity)iter.next();
          Attributes attrs=entity.getAttributes();
          Attribute attr=null;
          NamingEnumeration nenum=attrs.getIDs();
          try {
            while(nenum.hasMore()){
              String id=(String)nenum.next();
              attr=attrs.get(id);
              _log.debug(" Attribute for entity : " + entity.getName() +"Att value  : "+ attr.get());
            }
          }
          catch (Exception exp) {
            _log.debug("Got Naming exp :"+ exp.getMessage());
          }

        }
        _log.debug("Printing all entities and their attributes for community : "+ community.getName()+
                   " For Agent : "+_agent+  "   Done .............   :");
      }
      isAgentMnRManager(community,_agent);
      if (isManagedCommunity(community, _agent)) {
        if (_log.isDebugEnabled()) {
          _log.debug(" Received managed community in GetManagedCommunity listener :"+ community.getName());
        }
        _cs.removeListener(this);
        if (_log.isDebugEnabled()) {
          _log.debug("Calling the registered listener : "+_listener); 
        }
        _listener.getResponse(Collections.singleton(community));
        if (_log.isDebugEnabled()) {
          _log.debug("Managed security community found: " + 
                     community.getName() + "  For agent : "+_agent);
        }
      }
      if (_log.isDebugEnabled()) {
        _log.debug("GetManagedCommunity Listener Done  ..................... :");
      }
    }
    public String getCommunityName() {
      return null; // all MY communities
    }
  };
      

}
