/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */
package org.cougaar.core.security.acl.user;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.blackboard.SubscriptionWatcher;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.acl.user.CasRelay.CasResponse;
import org.cougaar.core.security.services.acl.UserService;
import org.cougaar.core.security.services.acl.UserServiceException;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.security.util.CommunityServiceUtilListener;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.Entity;
import org.cougaar.core.service.AgentIdentificationService;

import org.cougaar.util.UnaryPredicate;


import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class AgentUserService implements UserService, BlackboardClient {

  private ServiceBroker _serviceBroker;
  private CommunityService _communityService;
  private BlackboardService _bbs;
  private LoggingService _log;
  private UIDService     _uidService;
  private MessageAddress _source;
  private Set            _myRelays = new HashSet();
  private Object         _lock = new Object();
  private IncrementalSubscription _subscription;
  private HashMap        _targets = new HashMap();
  private String         _defaultDomain;
  private CommunityServiceUtil _csu;
  public  static final String COMMUNITY_TYPE = "User";
  public  static final String MANAGER_ROLE   = "UserManager";
  public final static long MAX_WAIT = 10000;

  private final UnaryPredicate MY_RELAYS = new UnaryPredicate() {
      public boolean execute(Object obj) {
        synchronized (_myRelays) {
          return _myRelays.contains(obj);
        }
      }
    };

  private final SubscriptionWatcher WATCHER = new SubscriptionWatcher() {
      public void signalNotify(int event) {
        super.signalNotify(event);
        synchronized(_lock) {
          _lock.notifyAll();
        }
      }
    };
  public AgentUserService(ServiceBroker sb) {
    _serviceBroker = sb;
    _log = (LoggingService)
      _serviceBroker.getService(this, LoggingService.class, null);
    _bbs = (BlackboardService) 
      _serviceBroker.getService(this, BlackboardService.class, null);
    _uidService = (UIDService)
      _serviceBroker.getService(this, UIDService.class, null);
    AgentIdentificationService _agentIdentificationservice=(AgentIdentificationService)
      _serviceBroker.getService(this, AgentIdentificationService.class, null);
    if(_agentIdentificationservice!=null) {
      _source = _agentIdentificationservice.getMessageAddress();
      if(_log.isDebugEnabled()){
        _log.debug("Setting agent source as "+_source);
      }
    }
    else {
      if(_log.isDebugEnabled()){
        _log.debug("AgentIdentificationservice service is not avilable ");
        _log.debug("AddingListener for AgentIdentificationservice ");
      }
      _serviceBroker.addServiceListener(new AgentIdentificationServiceListener());
    }
    CommunityService cs = (CommunityService)
      _serviceBroker.getService(this, CommunityService.class, null);
    if (cs == null) {
      if(_log.isDebugEnabled()){
        _log.debug("CommunityService service is not avilable ");
      }
      _serviceBroker.addServiceListener(new CommunityServiceListener());
    } else {
      if(_log.isDebugEnabled()){
        _log.debug("set communityService called ");
      }
      setCommunityService(cs);
    }
    if (_bbs != null) {
      startSubscription();
    } else {
      if(_log.isDebugEnabled()){
        _log.debug("BB service is not avilable ");
      }
      _serviceBroker.addServiceListener(new BlackboardServiceListener());
    }
  }
  
  public AgentUserService(ServiceBroker sb, MessageAddress agent) {
    _serviceBroker = sb;
    _log = (LoggingService)
      _serviceBroker.getService(this, LoggingService.class, null);
    _bbs = (BlackboardService) 
      _serviceBroker.getService(this, BlackboardService.class, null);
    _uidService = (UIDService)
      _serviceBroker.getService(this, UIDService.class, null);
    _source = agent;
    CommunityService cs = (CommunityService)
      _serviceBroker.getService(this, CommunityService.class, null);
    if (cs == null) {
      if(_log.isDebugEnabled()){
        _log.debug("CommunityService service is not avilable ");
      }
      _serviceBroker.addServiceListener(new CommunityServiceListener());
    } else {
      if(_log.isDebugEnabled()){
        _log.debug("set communityService called ");
      }
      setCommunityService(cs);
    }

    if (_bbs != null) {
      startSubscription();
    } else {
      if(_log.isDebugEnabled()){
        _log.debug("BB service is not avilable ");
      }
      _serviceBroker.addServiceListener(new BlackboardServiceListener());
    }
  }

  private void startSubscription() {
    _bbs.openTransaction();
    _subscription = (IncrementalSubscription) _bbs.subscribe(MY_RELAYS);
    _bbs.registerInterest(WATCHER);
    _bbs.closeTransaction();
    if(_log.isDebugEnabled()){
      _log.debug("Set up startSubscription done so Agent User service should be up");
    }
  }

  private synchronized void setCommunityService(CommunityService cs) {
    if (_csu == null) {
      _csu = new CommunityServiceUtil(_serviceBroker);
      CommunityServiceUtilListener listener = 
        new CommunityServiceUtilListener() {
          public void getResponse(Set agents) {
            if(_log.isDebugEnabled()){
              _log.debug("received Response from communityService util in AgentUserService calling setupRoles:"+ agents.toString());
            }
            setupRole(agents);
          }
        };
      if(_log.isDebugEnabled()){
        _log.debug("Calling communityservice util to find agents from community "+ COMMUNITY_TYPE +
                   "role "+ MANAGER_ROLE);
      }
      _csu.getCommunityAgent(COMMUNITY_TYPE, MANAGER_ROLE, listener);
    }
  }

  private void setupRole(Collection agents) {
    final Entity agent = (Entity) agents.iterator().next();

    CommunityServiceUtilListener listener = 
      new CommunityServiceUtilListener() {
        public void getResponse(Set communities) {
          Iterator iter = communities.iterator();
          while (iter.hasNext()) {
            Community community = (Community) iter.next();
            if(_log.isDebugEnabled()){
              _log.debug(" doing community search (Role="+ MANAGER_ROLE +") agents only "); 
            }
            Set agents = community.search("(Role=" + MANAGER_ROLE + ")",
                                          Community.AGENTS_ONLY);
            if (agents.contains(agent)) {
              // this is the one!
              String agentName = agent.getName();
              String communityName = community.getName();
              if (agentName.equals(_source.toString())) {
                synchronized (_targets) {
                  _targets.put(communityName, _source);
                }
              }
              _defaultDomain = communityName;
              if (_log.isDebugEnabled()) {
                _log.debug("Setting default domain: " + _defaultDomain);
              }
              return;
            }
          }
          _log.error("Community information mismatch! Found agent that " +
                     "isn't part of any community that I belong to: " +
                     agent);
        }
      };
    _csu.getCommunity(COMMUNITY_TYPE, listener);
  }

  public long currentTimeMillis() {
    return System.currentTimeMillis();
  }

  public String getBlackboardClientName() {
    return "AgentUserService";
  }

  public boolean triggerEvent(Object event) {
    return false;
  }
  
  private String getDomain(String id) throws UserServiceException {
    int index = id.indexOf("\\");
    if (index == -1) {
      return _defaultDomain;
    }
    return id.substring(0, index);
  }

  private MessageAddress getTarget(String id) throws UserServiceException {
    return findTargetAgent(getDomain(id));
  }

  private MessageAddress findTargetAgent(String communityName) 
    throws UserServiceException {
    final boolean debug = _log.isDebugEnabled();

    if (debug) {
      _log.debug("looking for community " + communityName);
    }
    if (communityName == null) {
      String message = "The user has no domain and there " +
        "is no default for this agent.";
      _log.debug(message);
      throw new UserServiceException(message);
    }
    synchronized (_targets) {
      MessageAddress target = (MessageAddress) _targets.get(communityName);
      if (target != null) {
        _log.debug("found manager in cache: " + target);
        return target;
      }

      if (_csu == null) {
	String message = "User attempting to login before community " +
	  "service is available";
	_log.debug(message);
	throw new UserServiceException(message);
      }

      Set agents = _csu.getAgents(communityName, MANAGER_ROLE, MAX_WAIT);
      if (debug) {
        _log.debug("agent list is " + agents);
      }
      if (agents == null || agents.size() != 1) {
        String message = "Could not find manager for community" +
          communityName;
        _log.debug(message);
        throw new UserServiceException(message);
      }
      Entity entity = (Entity) agents.iterator().next();
      target = MessageAddress.getMessageAddress(entity.getName());
      if (debug) {
        _log.debug("Found manager for " + communityName + ": " + target);
      }
      _targets.put(communityName, target);
      return target;
    }
  }

  private class Status {
    public Object value;
  }

  private String getId(String id) {
    int index = id.indexOf("\\");
    if (index != -1) {
      return id.substring(index + 1);
    }
    return id;
  }

  private Object waitResponse(CasRelay relay) throws UserServiceException {
    CasResponse response = null;
    synchronized (_myRelays) {
      _myRelays.add(relay);
    }
    if (_log.isDebugEnabled()) {
      _log.debug("sending: " + relay);
    }
    try {
      _bbs.openTransaction();
      if(_log.isDebugEnabled()){
        _log.debug("Publishing relay in wait response :"+relay.toString());
      }
      _bbs.publishAdd(relay);
      _bbs.closeTransaction();
    } catch (Exception e) {
      e.printStackTrace();
    }
    synchronized (_lock) {
      while ((response = (CasResponse)relay.getResponse()) == null) {
        try {
          _lock.wait();
        } catch (Exception e) {
          if (_log.isWarnEnabled()) {
            _log.warn("Exception while waiting on lock: " + e.toString());
          }
        }
      }
      if (_log.isDebugEnabled()) {
        _log.debug("Got Response: " + relay);
      }
    }
    synchronized (_myRelays) {
      _myRelays.remove(relay);
    }
    _bbs.openTransaction();
    _bbs.publishRemove(relay);
    _bbs.closeTransaction();
    if (response.isOk()) {
      return response.getResponse();
    }
    throw (UserServiceException) response.getResponse();
  }


  public void disableUser(String uid) throws UserServiceException {
    MessageAddress target = getTarget(uid);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.disableUser(getId(uid));
    waitResponse(relay);
  }

  public void lockCertificate(String uid) throws UserServiceException {
  }

  public void unlockCertificate(String uid) throws UserServiceException {
  }

  public void disableUser(String uid, long milliseconds) 
    throws UserServiceException {
    MessageAddress target = getTarget(uid);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.disableUser(getId(uid), milliseconds);
    waitResponse(relay);
  }

  public void enableUser(String uid) 
    throws UserServiceException {
    MessageAddress target = getTarget(uid);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.enableUser(getId(uid));
    waitResponse(relay);
  }

  public Set getUsers(String domain, String text, 
                      String field, int maxResults) 
    throws UserServiceException {
    if (domain == null) {
      domain = _defaultDomain;
    }
    MessageAddress target = findTargetAgent(domain);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.getUsers(text, field, maxResults);
    return setIdDomains((Set) waitResponse(relay), domain);
  }

  public Map getUser(String uid) throws UserServiceException {
    String domain = getDomain(uid);
    MessageAddress target = findTargetAgent(domain);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.getUser(getId(uid));
    Map user =  changeMapId((Map) waitResponse(relay), 
                            UserEntries.FIELD_UID, domain);
    if (user != null) {
      Set roles = (Set) user.get(getRoleListAttribute());
      if (roles != null) {
        user.put(getRoleListAttribute(), setIdDomains(roles, domain));
      }
    }
    return user;
  }

  public void editUser(String uid, Map added, Map edited, Set deleted)
    throws UserServiceException {
    MessageAddress target = getTarget(uid);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.editUser(getId(uid), added, edited, deleted);
    waitResponse(relay);
  }

  public void addUser(String uid, Map map) throws UserServiceException {
    MessageAddress target = getTarget(uid);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.addUser(getId(uid), map);
    waitResponse(relay);
  }

  public void deleteUser(String uid) throws UserServiceException {
    MessageAddress target = getTarget(uid);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.deleteUser(getId(uid));
    waitResponse(relay);
  }

  private static Set setIdDomains(Set ids, String domain) {
    Iterator iter = ids.iterator();
    Set newSet = new HashSet();
    while (iter.hasNext()) {
      String id = (String) iter.next();
      newSet.add(domain + "\\" + id);
    }
    return newSet;
  }

  public Set getRoles(String uid) throws UserServiceException {
    String domain = getDomain(uid);
    MessageAddress target = findTargetAgent(domain);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.getRoles(getId(uid));
    return setIdDomains( (Set) waitResponse(relay), domain);
  }

  public Set getRoles(String domain, String searchText, 
                      String field, int maxResults) 
    throws UserServiceException {
    if (domain == null) {
      domain = _defaultDomain;
    }
    MessageAddress target = findTargetAgent(domain);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.getRoles(searchText, field, maxResults);
    return setIdDomains((Set) waitResponse(relay), domain);
  }

  public Set getRoles(String domain, int maxResults) 
    throws UserServiceException {
    if (domain == null) {
      domain = _defaultDomain;
    }
    MessageAddress target = findTargetAgent(domain);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.getRoles(maxResults);
    return setIdDomains((Set) waitResponse(relay), domain);
  }

  private Map changeMapId(Map map, String key, String domain) {
    if (map != null) {
      String id = (String) map.get(key);
      if (id != null) {
        map.put(key, domain + "\\" + id);
      }
    }
    return map;
  }

  public Map getRole(String rid) throws UserServiceException {
    String domain = getDomain(rid);
    MessageAddress target = findTargetAgent(domain);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.getRole(getId(rid));
    Map role = changeMapId((Map) waitResponse(relay), UserEntries.FIELD_RID,
                           domain);
    Set roles = (Set) role.get(getRoleListAttribute());
    if (roles != null) {
      role.put(getRoleListAttribute(), setIdDomains(roles, domain));
    }
    return role;
  }

  public void assign(String uid, String rid) 
    throws UserServiceException {
    MessageAddress target = getTarget(rid);
    MessageAddress target2 = getTarget(uid);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    if (!target.equals(target2)) {
      throw new UserServiceException("Domains must be the same for user and role");
    }
    relay.assign(getId(uid), getId(rid));
    waitResponse(relay);
  }

  public void addRoleToRole(String container, String containee) 
    throws UserServiceException {
    MessageAddress target = getTarget(container);
    MessageAddress target2 = getTarget(containee);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    if (!target.equals(target2)) {
      throw new UserServiceException("Role domains must be the same");
    }
    relay.addRoleToRole(getId(container), getId(containee));
    waitResponse(relay);
  }

  public void unassign(String uid, String rid) throws UserServiceException {
    MessageAddress target = getTarget(uid);
    MessageAddress target2 = getTarget(rid);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    if (!target.equals(target2)) {
      throw new UserServiceException("Domains must be the same for user and role");
    }
    relay.unassign(getId(uid), getId(rid));
    waitResponse(relay);
  }

  public void removeRoleFromRole(String container, String containee) 
    throws UserServiceException {
    MessageAddress target = getTarget(container);
    MessageAddress target2 = getTarget(containee);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    if (!target.equals(target2)) {
      throw new UserServiceException("Role domains must be the same");
    }
    relay.removeRoleFromRole(getId(container), getId(containee));
    waitResponse(relay);
  }

  public void addRole(String rid) throws UserServiceException {
    MessageAddress target = getTarget(rid);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.addRole(getId(rid));
    waitResponse(relay);
  }

  public Set expandRoles(String rids[]) throws UserServiceException {
    if (rids == null || rids.length == 0) return null;
    String domain = null;
    String newRids[] = new String[rids.length];
    for (int i = 0; i < rids.length; i++) {
      if (domain == null) {
        domain = getDomain(rids[i]);
      } else if (!domain.equals(getDomain(rids[i]))) {
        throw new UserServiceException("Role domains must be the same"); 
      }
      newRids[i] = getId(rids[i]);
    }
    MessageAddress target = findTargetAgent(domain);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.expandRoles(newRids);
    return setIdDomains((Set) waitResponse(relay), domain);
  }

  public Set getUsersInRole(String rid)  throws UserServiceException {
    String domain = getDomain(rid);
    MessageAddress target = findTargetAgent(domain);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.getUsersInRole(getId(rid));
    return setIdDomains((Set) waitResponse(relay), domain);
  }

  public Set getContainedRoles(String rid) throws UserServiceException {
    String domain = getDomain(rid);
    MessageAddress target = findTargetAgent(domain);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.getContainedRoles(getId(rid));
    return setIdDomains((Set) waitResponse(relay), domain);
  }

  public void addRole(String rid, Map map) throws UserServiceException {
    MessageAddress target = getTarget(rid);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.addRole(getId(rid), map);
    waitResponse(relay);
  }

  public void editRole(String rid, Map added, Map edited, Set deleted) 
    throws UserServiceException {
    MessageAddress target = getTarget(rid);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.editRole(getId(rid), added, edited, deleted);
    waitResponse(relay);
  }

  public void deleteRole(String rid) throws UserServiceException {
    MessageAddress target = getTarget(rid);
    CasRelay relay = new CasRelay(_uidService.nextUID(), _source, target);
    relay.deleteRole(getId(rid));
    waitResponse(relay);
  }

  public String getRoleListAttribute() {
    return UserEntries.FIELD_ROLE_LIST;
  }

  public String  getPasswordAttribute() {
    return UserEntries.FIELD_PASSWORD;
  }

  public String getAuthFieldsAttribute() {
    return UserEntries.FIELD_AUTH;
  }

  public String getEnableTimeAttribute() {
    return UserEntries.FIELD_ENABLE_TIME;
  }

  public String getUserIDAttribute() {
    return UserEntries.FIELD_UID;
  }

  public String getRoleIDAttribute() {
    return UserEntries.FIELD_RID;
  }

  public String getCertOkAttribute() {
    return UserEntries.FIELD_CERT_OK;
  }

  public String getDefaultDomain() {
    return _defaultDomain;
  }

  private class CommunityServiceListener implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      if (ae.getService().equals(CommunityService.class)) {
        CommunityService cs = (CommunityService) ae.getServiceBroker().
          getService(this, CommunityService.class, null);
        if (cs != null) {
          ae.getServiceBroker().removeServiceListener(this);
          _log.debug("Got Community service starting community search  for AgentUser service");
          setCommunityService(cs);
        }
      }
    }
  }

  private class BlackboardServiceListener implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      if (ae.getService().equals(BlackboardService.class)) {
        _bbs = (BlackboardService) ae.getServiceBroker().
          getService(AgentUserService.this, BlackboardService.class, null);
        if (_bbs != null) {
          ae.getServiceBroker().removeServiceListener(this);
          startSubscription();
        }
      }
    }
  }
  
  private class AgentIdentificationServiceListener implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      if (ae.getService().equals(AgentIdentificationService.class)) {
        AgentIdentificationService ais = (AgentIdentificationService) ae.getServiceBroker().
          getService(this, AgentIdentificationService.class, null);
        if (ais != null) {
          ae.getServiceBroker().removeServiceListener(this);
          _log.debug("Got agent AgentIdentificationService service User service provider service");
          _source=ais.getMessageAddress();
        }
      }
    }
  }
}
