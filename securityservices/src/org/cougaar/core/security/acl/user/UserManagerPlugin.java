/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
 
package org.cougaar.core.security.acl.user;

// cougaar core classes
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.acl.user.CasRelay.CasRequest;
import org.cougaar.core.security.acl.user.CasRelay.CasResponse;
import org.cougaar.core.security.services.acl.UserServiceException;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.security.util.CommunityServiceUtilListener;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.util.UnaryPredicate;

/**
 * @author srosset
 *
 * This UserManagerPlugin class provides the following capabilities:
 *  - Reading a list of users and passwords from a configuration file.
 *  - Storing users and passwords on the blackboard.
 *  - Processing requests from remote agents, such as authentication users.
 */
public class UserManagerPlugin extends ComponentPlugin {
  private DomainService    _domainService;
  private LoggingService   _log;

  private IncrementalSubscription _relaySub;
  private UserEntries      _userCache;
  private String           _domain;

  private boolean          _rehydrated = false;

  private static final CasResponse RESPONSE_OK = new CasResponse(null);
  private static final UnaryPredicate USER_ENTRIES = new UnaryPredicate() {
      public boolean execute(Object obj) {
        return (obj instanceof UserEntries);
      }
    };

  public UserManagerPlugin() {
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return _domainService;
  }

  /**
   * Agent uses this to set the domain service
   */
  public void setDomainService(DomainService aDomainService) {
    _domainService = aDomainService;
    _log = (LoggingService) getServiceBroker().
      getService(this, LoggingService.class, null);
  }

  public void setParameter(Object o) {
    List l = (List) o;
    
    if (l.size() > 1) {
      _log.warn("Unexpected number of parameters given. Expecting 1, got " +
                l.size());
    }
  }

  private class Status {
    public Object value;
  }

  private void setDomain() {
    final CommunityServiceUtil csu = 
      new CommunityServiceUtil(getServiceBroker());
    CommunityServiceUtilListener listener = 
      new CommunityServiceUtilListener() {
        public void getResponse(Set communities) {
          _domain = communities.iterator().next().toString();
          if (_log.isDebugEnabled()) {
            _log.debug("Domain for this user manager is " + _domain);
          }
          csu.releaseServices();
          if (!_rehydrated) {
            _userCache.setDomain(_domain);
            UserFileParser ufp = new UserFileParser(_userCache);
            ufp.readUsers();
          }
        }
      };
    csu.getCommunity(AgentUserService.COMMUNITY_TYPE, 
                     AgentUserService.MANAGER_ROLE, listener);
  }

  /**
   * Register this sensor's capabilities
   */
  protected void setupSubscriptions() {
    BlackboardService bbs = getBlackboardService();
    Collection entries = bbs.query(USER_ENTRIES);
    if (entries.size() != 0) {
      _userCache = (UserEntries) entries.iterator().next();
      _log.info("Rehydrating with " + _userCache.getUserCount() +
                " users and " + _userCache.getRoleCount() + 
                " roles");
      _rehydrated = true;
      // also process the relays left on the blackboard
      process(bbs.query(UNANSWERED_CAS_TARGETS));
    } else {
      UIDService uidService = (UIDService)
        getServiceBroker().getService(this, UIDService.class, null);
      _userCache = new UserEntries(uidService.nextUID());
      getBlackboardService().publishAdd(_userCache);

    }

    CommunityService cs = (CommunityService)
      getServiceBroker().getService(this, CommunityService.class, null);
    AgentIdentificationService ais = (AgentIdentificationService)
      getServiceBroker().getService(this, AgentIdentificationService.class,
                                    null);
    if (cs == null || ais == null) {
      getServiceBroker().addServiceListener(new MyServiceListener(ais, cs));
    } else {
      setDomain();
      getServiceBroker().releaseService(this, CommunityService.class, cs);
      getServiceBroker().releaseService(this, AgentIdentificationService.class,
                                        ais);
    }
    _relaySub = (IncrementalSubscription) 
      getBlackboardService().subscribe(CAS_TARGETS);
  }

  public void execute() {
    if (_log.isDebugEnabled()) {
      _log.debug("Execute called: _relaySub.hasChanged(): " + _relaySub.hasChanged());
    }
    if (_relaySub.hasChanged()) {
      if (_log.isDebugEnabled()) {
        _log.debug("Added: " + _relaySub.getAddedCollection().size());
      }
      Collection added = _relaySub.getAddedCollection();
      process(added);
    }
  }

  private void process(Collection added) {
    Iterator iter = added.iterator();
    while (iter.hasNext()) {
      CasRelay relay = (CasRelay) iter.next();
      if (_log.isDebugEnabled()) {
	_log.debug("Relay: " + relay);
      }
      CasRequest request = (CasRequest) relay.getContent();
      try {
	CasResponse response = getResponse(request);
	relay.setResponse(response);
	getBlackboardService().publishChange(relay);
      } catch (Exception e) {
	_log.warn("Caught exception when setting the response", e);
      }
      if (_log.isDebugEnabled()) {
	_log.debug("Responded to relay: " + relay);
      }
    } // end of while (iter.hasNext())
  }
  

  private CasResponse getResponse(CasRequest request) {
    try {
      Object arg = request.getArgs();
      Object arr[] = null;
      if (arg instanceof Object[]) {
        arr = (Object[]) arg;
      }
      Object response = null;

      switch (request.getType()) {
      case CasRelay.LOCK_USER: 
        _userCache.disableUser((String) arg);
        break;
      case CasRelay.LOCK_USER_4_TIME:
        _userCache.disableUser((String) arr[0], ((Long) arr[1]).longValue());
        break;
      case CasRelay.UNLOCK_USER:
        _userCache.enableUser((String) arg);
        break;
      case CasRelay.SEARCH_USERS:
        response = _userCache.getUsers((String) arr[0], 
                                       (String) arr[1],
                                       ((Integer)arr[2]).intValue());
        break;
      case CasRelay.GET_USER:
        response = _userCache.getUser((String) arg);
        break;
      case CasRelay.EDIT_USER:
        _userCache.editUser((String) arr[0], (Map) arr[1], (Map) arr[2],
                            (Set) arr[3]);
        break;
      case CasRelay.ADD_USER:
        _userCache.addUser((String) arr[0], (Map) arr[1]);
        break;
      case CasRelay.DEL_USER:
        _userCache.deleteUser((String) arg);
        break;
      case CasRelay.GET_USER_ROLES:
        response = _userCache.getRoles((String) arg);
        break;
      case CasRelay.SEARCH_ROLES:
        response = _userCache.getRoles((String) arr[0], (String) arr[1], 
                                       ((Integer) arr[2]).intValue());
        break;
      case CasRelay.GET_ROLES:
        response = _userCache.getRoles(((Integer) arg).intValue());
        break;
      case CasRelay.GET_ROLE:
        response = _userCache.getRole((String) arg);
        break;
      case CasRelay.ROLE2USER:
        _userCache.assign((String) arr[0], (String) arr[1]);
        break;
      case CasRelay.UNASSIGN_USER:
        _userCache.unassign((String) arr[0], (String) arr[1]);
        break;
      case CasRelay.ADD_ROLE:
        _userCache.addRole((String) arr[0], (Map) arr[1]);
        break;
      case CasRelay.EDIT_ROLE:
        _userCache.editRole((String) arr[0], (Map) arr[1], (Map) arr[2],
                            (Set) arr[3]);
        break;
      case CasRelay.ROLE2ROLE:
        _userCache.addRoleToRole((String) arr[0], (String) arr[1]);
        break;
      case CasRelay.UNASSIGN_ROLE:
        _userCache.removeRoleFromRole((String) arr[0], (String) arr[1]);
        break;
      case CasRelay.EXPAND_ROLES:
        response = _userCache.expandRoles((String[]) arg);
        break;
      case CasRelay.GET_SUB_ROLES:
        response = _userCache.getContainedRoles((String) arg);
        break;
      case CasRelay.GET_ROLE_USERS:
        response = _userCache.getUsersInRole((String) arg);
        break;
      case CasRelay.DEL_ROLE:
        _userCache.deleteRole((String) arg);
        break;
      }
      if (response == null) {
        return RESPONSE_OK;
      }
      return new CasResponse(response);
    } catch (UserServiceException e) {
      return new CasResponse(e);
    }
  }

  private static final UnaryPredicate CAS_TARGETS = 
    new UnaryPredicate() {
      //   Logger _log = LoggerFactory.getInstance().createLogger(this);
        public boolean execute(Object obj) {
          /* debug code 
             if (_log.isDebugEnabled()) {
            _log.debug("Comparing against object of class: " + obj.getClass().getName() + " will return " + (obj instanceof CasRelay && 
                   ((CasRelay) obj).isTarget()));
           }
           */
           return (obj instanceof CasRelay && 
                   ((CasRelay) obj).isTarget());
        }
    };

  private static final UnaryPredicate UNANSWERED_CAS_TARGETS = 
    new UnaryPredicate() {
        public boolean execute(Object obj) {
          return (obj instanceof CasRelay && 
                  ((CasRelay) obj).isTarget() &&
		  ((CasRelay) obj).getResponse() == null);
        }
      };


  private class MyServiceListener implements ServiceAvailableListener {
    private AgentIdentificationService _ais;
    private CommunityService           _cs;
    private boolean                    _completed;

    public MyServiceListener(AgentIdentificationService ais,
                             CommunityService cs) {
      _ais = ais;
      _cs = cs;
    }

    public void serviceAvailable(ServiceAvailableEvent ae) {
      if (_cs == null && ae.getService().equals(CommunityService.class)) {
        _cs = (CommunityService) ae.getServiceBroker().
           getService(UserManagerPlugin.this, CommunityService.class, null);
      } else if (_ais == null &&
                 ae.getService().equals(AgentIdentificationService.class)) {
        _ais = (AgentIdentificationService) ae.getServiceBroker().
          getService(UserManagerPlugin.this, AgentIdentificationService.class,
                     null);
      }
      if (_ais != null && _cs != null) {
        ae.getServiceBroker().removeServiceListener(this);
        if (!_completed) {
          _completed = true;
          setDomain();
          getServiceBroker().releaseService(UserManagerPlugin.this, 
                                            CommunityService.class, _cs);
          getServiceBroker().releaseService(UserManagerPlugin.this, 
                                            AgentIdentificationService.class,
                                            _ais);
        }
      }
    }
  }
}
