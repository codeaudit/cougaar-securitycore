/**
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
 *
 */

package org.cougaar.core.security.access;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityChangeEvent;
import org.cougaar.core.service.community.CommunityChangeListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.FindCommunityCallback;

import java.util.Collection;
import java.util.Hashtable;

import javax.naming.directory.Attributes;
import javax.naming.directory.ModificationItem;

// this class is a proxy for the community service 
class CommunityServiceProxy extends SecureServiceProxy 
  implements CommunityService {
  private final CommunityService _cs;
  private final Object _requestor;
  // community change listeners
  private static Hashtable _listeners = new Hashtable();
  
  public CommunityServiceProxy(CommunityService cs, Object requestor, ServiceBroker sb) {
    super(sb);
    _cs = cs;
    _requestor = requestor;
  }

  /*
  public boolean createCommunity(String communityName, Attributes attributes) {
    return _cs.createCommunity(communityName, attributes);
  }
  */
  public void createCommunity(String communityName, Attributes attrs, 
    CommunityResponseListener crl) {
    _cs.createCommunity(communityName, attrs, createSecureResponse(crl));
  }

  public Community getCommunity(String communityName, CommunityResponseListener crl) {
    return _cs.getCommunity(communityName, createSecureResponse(crl));
  }
  
  public void joinCommunity(String communityName, String entityName, int entityType, 
    Attributes entityAttrs, boolean createIfNotFound, Attributes newCommunityAttrs, 
    CommunityResponseListener crl) {
    _cs.joinCommunity(communityName, entityName, entityType, entityAttrs,
      createIfNotFound, newCommunityAttrs, createSecureResponse(crl));
  }
  
  public void leaveCommunity(String communityName, String entityName, 
    CommunityResponseListener crl) {
    _cs.leaveCommunity(communityName, entityName, createSecureResponse(crl));
  }

  public void modifyAttributes(String communityName, String entityName, 
    ModificationItem[] mods, CommunityResponseListener crl) {
    _cs.modifyAttributes(communityName, entityName, mods, createSecureResponse(crl));
  }

  public void addListener(CommunityChangeListener l) {
    _cs.addListener(addChangeListener(l));
  }
  
  /*
  public boolean addListener(MessageAddress addr, String communityName) {
    return _cs.addListener(addr, communityName);
  }
  */
  /*
  public boolean addRole(String communityName, String entityName, String roleName) {
    return _cs.addRole(communityName, entityName, roleName);
  }
  */
  /*
  public boolean addToCommunity(String communityName, Object entity, 
    String entityName, Attributes attributes) {
    return _cs.addToCommunity(communityName, entity, entityName, attributes);    
  }
  public boolean communityExists(String communityName) {
    return _cs.communityExists(communityName);
  }
  public Attributes getCommunityAttributes(String communityName) {
    return _cs.getCommunityAttributes(communityName);
  }
  public Collection getCommunityRoles(String communityName) {
    return _cs.getCommunityRoles(communityName);
  }
  public Attributes getEntityAttributes(String communityName, String entityName) {
    return _cs.getEntityAttributes(communityName, entityName);
  }
  public Collection getEntityRoles(String communityName, String entityName) {
    return _cs.getEntityRoles(communityName, entityName);
  }
  public Collection getListeners(String communityName) {
    return _cs.getListeners(communityName);
  }
  */
  public String [] getParentCommunities(boolean allLevels) {
    return _cs.getParentCommunities(allLevels);
  }
  
/*
  public CommunityRoster getRoster(String communityName) {
    return _cs.getRoster(communityName);
  }
*/
  public Collection listAllCommunities() {
    return _cs.listAllCommunities();
  }
  public void listAllCommunities(CommunityResponseListener crl) {
    _cs.listAllCommunities(crl);
  }
/*
  public Collection listEntities(String communityName) { 
    return _cs.listEntities(communityName);
  }
*/
  public void findCommunity(String                communityName,
			    FindCommunityCallback fccb,
			    long                  timeout) {
    _cs.findCommunity(communityName, fccb, timeout);
  }

  public Collection listParentCommunities(String member) {
    return _cs.listParentCommunities(member);
  }
  public Collection listParentCommunities(String member, String filter) {
    return _cs.listParentCommunities(member, filter);
  } 
  public Collection listParentCommunities(String member,
					  CommunityResponseListener crl) {
    return _cs.listParentCommunities(member, crl);
  } 
  public Collection listParentCommunities(String member,
					  String filter,
					  CommunityResponseListener crl) {
    return _cs.listParentCommunities(member, crl);
  } 
/*
  public boolean modifyCommunityAttributes(String communityName, 
    ModificationItem[] mods) { 
    return _cs.modifyCommunityAttributes(communityName, mods);
  }
  public boolean modifyEntityAttributes(String communityName, 
    String entityName, ModificationItem[] mods) {
    return _cs.modifyEntityAttributes(communityName, entityName, mods);  
  }
  public boolean removeFromCommunity(String communityName, String entityName) {
    return _cs.removeFromCommunity(communityName, entityName);
  }
*/
  public void removeListener(CommunityChangeListener l) {
    _cs.removeListener(removeChangeListener(l));
  }
/*
  public boolean removeListener(MessageAddress addr, String communityName) {
    return _cs.removeListener(addr, communityName);
  }
  public boolean removeRole(String communityName, String entityName, String roleName) {
    return _cs.removeRole(communityName, entityName, roleName);
  }
  public Collection search(String filter) { 
    return _cs.search(filter);
  }
*/
  public Collection search(String communityName, String filter) {
    return _cs.search(communityName, filter);
  }
/*
  public Collection search(String communityName, String filter, boolean blockingMode) {
    return _cs.search(communityName, filter, blockingMode);
  }
  public Collection searchByRole(String communityName, String roleName) {
    return _cs.searchByRole(communityName, roleName);
  }
*/
  // NOTE: return is void for this method but the API states that the return type is
  //       a Collection
  public Collection searchCommunity(String communityName, String searchFilter, 
    boolean recursiveSearch, int resultQualifier, CommunityResponseListener crl) {
    return _cs.searchCommunity(communityName, searchFilter, recursiveSearch, 
      resultQualifier, createSecureResponse(crl));
  }
  /*
  public boolean setCommunityAttributes(String communityName, Attributes attributes) {
    return _cs.setCommunityAttributes(communityName, attributes);
  }
  public boolean setEntityAttributes(String communityName, String entityName, 
    Attributes attributes) {
    return _cs.setEntityAttributes(communityName, entityName, attributes);
  }
  */
  private CommunityChangeListener addChangeListener(CommunityChangeListener listener) {
    SecureCommunityChangeListener scl =
      new SecureCommunityChangeListener(listener, _scs.getExecutionContext());
    _listeners.put(listener, scl);
    return scl;
  }
  
  private CommunityChangeListener removeChangeListener(CommunityChangeListener listener) {
    CommunityChangeListener l = (CommunityChangeListener)_listeners.remove(listener);
    return ((l != null) ? l : listener);
  }
  
  private CommunityResponseListener createSecureResponse(CommunityResponseListener crl) {
    if (crl == null) {
      return null;
    }
    return new SecureCommunityResponseListener(crl, _scs.getExecutionContext()); 
  }
  class SecureCommunityChangeListener implements CommunityChangeListener {
    CommunityChangeListener _listener;
    ExecutionContext _ec;
    SecureCommunityChangeListener(CommunityChangeListener listener, ExecutionContext ec) {
      _listener = listener; 
      _ec = ec;
    }
    public void communityChanged(CommunityChangeEvent event) {
       _scs.setExecutionContext(_ec);
      _listener.communityChanged(event); 
      _scs.resetExecutionContext();
    }
    public String getCommunityName() {
      _scs.setExecutionContext(_ec);
      String retval = _listener.getCommunityName(); 
      _scs.resetExecutionContext();
      return retval;  
    }
  }// end class SecureCommunityChangeListener
  
  class SecureCommunityResponseListener implements CommunityResponseListener {
    CommunityResponseListener _listener;
    ExecutionContext _ec;
    SecureCommunityResponseListener(CommunityResponseListener listener, ExecutionContext ec) {
      if (listener == null) {
	throw new IllegalArgumentException("CommunityResponseListener cannot be null");
      }
      _listener = listener; 
      _ec = ec;
    }
    public void getResponse(CommunityResponse response)  {
       _scs.setExecutionContext(_ec);
      _listener.getResponse(response); 
      _scs.resetExecutionContext();
    }
  }// end class SecureCommunityResponseListener
}
