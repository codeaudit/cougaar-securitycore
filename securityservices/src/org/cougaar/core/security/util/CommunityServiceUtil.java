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

  private static final String MANAGER_ROLE = "Manager";

  /**
   * determine the m&r security managers for a given entity
   *
   * @param entity the agent or community
   * @return the message address of the m&r security manager
   */
  public void findSecurityManager(String entity,
				  final CommunityServiceUtilListener listener) {
    //MessageAddress myManager = null;
    //Iterator c = null;
    //String community = null;
    //Collection managers = null;
    //Collection communities = null;

    CommunityResponseListener crl = new CommunityResponseListener() {
	public void getResponse(CommunityResponse resp) {
	  Object response = resp.getContent();
	  if (!(response instanceof Set)) {
	    String errorString = "Unexpected community response class:"
	      + response.getClass().getName() + " - Should be a Set";
	    _log.error(errorString);
	    throw new RuntimeException(errorString);
	  }
          Set set = (Set) response;
          if (!set.isEmpty()) {
            listener.getResponse(set);
          } else {
            // wait for one to be there...
            _log.debug("Waiting for security manager to be available...");
            _cs.addListener(new GetSecurityManager(listener));
          }
	}
      };

    String filter = "(& (CommunityType=Security) (Role=" + MANAGER_ROLE +") )";
    Collection agents = 
      _cs.searchCommunity(null, filter, true, Community.AGENTS_ONLY, crl);
    if (agents != null) {
      listener.getResponse((Set) agents);
    }
  }

  public Community getSecurityCommunity(String agent) {
    Community myCommunity = null;
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
    String filter = "(CommunityType=Security)";
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
//         communities = Collection.singleton(listener.getCommunity());
        if (_log.isDebugEnabled()) {
          _log.debug(agent + " belongs to community " + 
                     listener.getCommunity().getName()); 
        }
        return listener.getCommunity();
      } catch (InterruptedException ie) {
        _log.error("Error in listening:", ie);
      }
    }
    if(communities.size() == 1) {
      myCommunity = (Community)communities.iterator().next();  
    }
    else {
      _log.debug("multiple security communities for " + agent);  
      Iterator it = communities.iterator();
      //Collection members = null;
      filter = "(& (CommunityType=Security) (Role=" + MANAGER_ROLE +") )";
      while(it.hasNext()) {
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
	if (myCommunity != null) {
	  break;
	}
      }
    }
    _log.debug("returning security community '" + myCommunity.getName() + "'");
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
    String filter = "(CommunityType=Security)";
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
        communities = Collection.singleton(listener.getCommunity());
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

  private static class GetSecurityCommunity 
    implements CommunityChangeListener {
    private Community _member;
    private Semaphore _semaphore;

    public GetSecurityCommunity(Semaphore s) {
      _semaphore = s;
    }

    public void communityChanged(CommunityChangeEvent event) {
      Community community = event.getCommunity();
      try {
        Attributes attrs = community.getAttributes();
        Attribute attr = attrs.get("CommunityType");
        if (attr != null) {
          for (int i = 0; i < attr.size(); i++) {
            Object type = attr.get(i);
            if (type.equals("Security")) {
              _member = community;
              _semaphore.release();
            }
          }
        }
      } catch (NamingException e) {
        throw new RuntimeException("This should never happen");
      }
    }
    public String getCommunityName() {
      return null; // all MY communities
    }

    public Community getCommunity() {
      return _member;
    }
  };

  private class GetSecurityManager 
    implements CommunityChangeListener {
    private CommunityServiceUtilListener _listener;

    public GetSecurityManager(CommunityServiceUtilListener listener) {
      _listener = listener;
    }

    public void communityChanged(CommunityChangeEvent event) {
      Community community = event.getCommunity();
      try {
        Attributes attrs = community.getAttributes();
        Attribute attr = attrs.get("CommunityType");
        if (attr == null) {
          return;
        }
        boolean isSecurity = false;
        for (int i = 0; i < attr.size(); i++) {
          Object type = attr.get(i);
          if (type.equals("Security")) {
            isSecurity = true;
            break;
          }
        }
        if (!isSecurity) {
          return;
        }
      } catch (NamingException e) {
        throw new RuntimeException("This should never happen");
      }
      Set set = community.search("(Role=" +MANAGER_ROLE + ')', 
                                 Community.AGENTS_ONLY);
      if (!set.isEmpty()) {
        _cs.removeListener(this);
        _listener.getResponse(set);
        if (_log.isDebugEnabled()) {
          _log.debug("Security manager found: " + set);
        }
      }
    }
    public String getCommunityName() {
      return null; // all MY communities
    }
  };
      

}
