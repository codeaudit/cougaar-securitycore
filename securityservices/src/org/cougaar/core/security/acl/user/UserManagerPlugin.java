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

package org.cougaar.core.security.acl.user;

// cougaar core classes
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.Entity;
import org.cougaar.core.service.community.CommunityChangeListener;
import org.cougaar.core.service.community.CommunityChangeEvent;
import org.cougaar.core.service.MessageProtectionService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.util.UniqueObject;
import org.cougaar.core.util.UID;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.util.ConfigFinder;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceAvailableEvent;

import EDU.oswego.cs.dl.util.concurrent.Semaphore;

// overlay class
import org.cougaar.core.security.constants.IdmefClassifications;

// securityservices classes
import org.cougaar.core.security.access.AccessAgentProxy;
import org.cougaar.core.security.crypto.CryptoManagerServiceImpl;
import org.cougaar.core.security.crypto.MessageProtectionServiceImpl;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.acl.user.CasRelay;
import org.cougaar.core.security.acl.user.CasRelay.CasRequest;
import org.cougaar.core.security.acl.user.CasRelay.CasResponse;
import org.cougaar.core.security.services.acl.UserServiceException;
import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;


// JavaIDMEF classes
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Alert;

// java classes
import java.util.*;
import java.io.*;
import javax.xml.parsers.*;
import org.xml.sax.SAXException;
import org.w3c.dom.*;
import org.w3c.dom.*;
import javax.naming.directory.*;
import javax.naming.*;

public class UserManagerPlugin extends ComponentPlugin {
  private DomainService    _domainService;
  private LoggingService   _log;

  private IncrementalSubscription _relaySub;
  //private CasRelay         _myRelay;
  private UserEntries      _userCache;
  private String           _domain;

  private static final CasResponse RESPONSE_OK = new CasResponse(null);
  public static final String ROLE_ASSIGNMENT = "role";
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

  private void setDomain(final CommunityService cs, 
                         AgentIdentificationService ais) {
    _log.debug("searching for domain for this manager");
    //String myAddress = ais.getName();

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
	  status.value = (Set) response;
	  s.release();
	}
      };
    // TODO: do this truly asynchronously.
    String filter = "(CommunityType=" + AgentUserService.COMMUNITY_TYPE + ")";
    Collection communities = cs.searchCommunity(null, filter, true,
                                                Community.COMMUNITIES_ONLY, 
                                                crl);
    if (communities == null) {
      try {
        s.acquire();
      } catch (InterruptedException ie) {
        _log.error("Error in searchByCommunity:", ie);
      }

      communities = (Set) status.value;
    }
    if (!communities.isEmpty()) {
      _domain = communities.iterator().next().toString();
      if (_log.isDebugEnabled()) {
        _log.debug("Domain for this user manager is " + _domain);
      }
    } else {
      CommunityChangeListener listener = new CommunityChangeListener() {
          public void communityChanged(CommunityChangeEvent event) {
            Community community = event.getCommunity();
            try {
              Attributes attrs = community.getAttributes();
              Attribute attr = attrs.get("CommunityType");
              if (attr != null) {
                for (int i = 0; i < attr.size(); i++) {
                  Object type = attr.get(i);
                  if (type.equals(AgentUserService.COMMUNITY_TYPE)) {
                    _domain = community.getName();
                    cs.removeListener(this);
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
        };
      cs.addListener(listener);
    }
  }

  /**
   * Register this sensor's capabilities
   */
  protected void setupSubscriptions() {
    CommunityService cs = (CommunityService)
      getServiceBroker().getService(this, CommunityService.class, null);
    AgentIdentificationService ais = (AgentIdentificationService)
      getServiceBroker().getService(this, AgentIdentificationService.class,
                                    null);
    if (cs == null || ais == null) {
      getServiceBroker().addServiceListener(new MyServiceListener(ais, cs));
    } else {
      setDomain(cs, ais);
      getServiceBroker().releaseService(this, CommunityService.class, cs);
      getServiceBroker().releaseService(this, AgentIdentificationService.class,
                                        ais);
    }
    BlackboardService bbs = getBlackboardService();
    Collection entries = bbs.query(USER_ENTRIES);
    if (entries.size() != 0) {
      _userCache = (UserEntries) entries.iterator().next();
      _log.info("Rehydrating with " + _userCache.getUserCount() +
                " users and " + _userCache.getRoleCount() + 
                " roles");
    } else {
      UIDService uidService = (UIDService)
        getServiceBroker().getService(this, UIDService.class, null);
      _userCache = new UserEntries(uidService.nextUID());
      getBlackboardService().publishAdd(_userCache);

      try {
        InputStream userIs = ConfigFinder.getInstance().open("UserFile.xml");
        if (userIs != null) {
          _log.info("Reading users from " + userIs);
          readUsers(userIs);
        } else {
          _log.info("UserFile.xml does not exist -- no users or role");
        }
      } catch (Exception e) {
        _log.warn("Couldn't load users from file: ", e);
      }
    }
    _relaySub = (IncrementalSubscription) 
      getBlackboardService().subscribe(CAS_TARGETS);
  }

  public void execute() {
    if (_relaySub.hasChanged()) {
      Iterator iter = _relaySub.getAddedCollection().iterator();
      while (iter.hasNext()) {
        CasRelay relay = (CasRelay) iter.next();
        CasRequest request = (CasRequest) relay.getContent();
        try {
          CasResponse response = getResponse(request);
          relay.setResponse(response);
          getBlackboardService().publishChange(relay);
        } catch (Exception e) {
          e.printStackTrace();
        }
        if (_log.isDebugEnabled()) {
          _log.debug("Responded to relay: " + relay);
        }
      } // end of while (iter.hasNext())
    }
  }
  
  private void readUsers(InputStream in) {
    try {
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      DocumentBuilder db = dbf.newDocumentBuilder();
      Document doc = db.parse(in);
      Element rootElement = doc.getDocumentElement();
      NodeList nodes = rootElement.getChildNodes();
      HashMap userAssigns = new HashMap();
      HashMap roleAssigns = new HashMap();
      for (int i = 0; i < nodes.getLength(); i++) {
        Node item = nodes.item(i);
        if (item instanceof Element) {
          Element l = (Element) item;
          Map map = readMap(l);
          Set groups = (Set) map.remove(ROLE_ASSIGNMENT);
          if ("user".equals(l.getNodeName())) {
            String pwd = (String) map.get(UserEntries.FIELD_PASSWORD);
            String user = (String) map.get(UserEntries.FIELD_UID);
            if (user == null) {
              _log.warn("No id for user entry");
              continue;
            }
            if (pwd != null) {
              pwd = KeyRingJNDIRealm.encryptPassword(_domain + "\\" + user, 
                                                     pwd);
            }
            map.put(UserEntries.FIELD_PASSWORD,pwd);
            _userCache.addUser(user, map);
            if (groups != null) {
              userAssigns.put(user, groups);
            }
          } else if ("role".equals(l.getNodeName())) {
            String role = (String) map.get(UserEntries.FIELD_RID);
            if (role == null) {
              _log.warn("No id for role entry");
              continue;
            }
            _userCache.addRole(role, map);
            if (groups != null) {
              roleAssigns.put(role, groups);
            }
          }
        }
      }
      Iterator assigns = userAssigns.entrySet().iterator();
      while (assigns.hasNext()) {
        Map.Entry entry = (Map.Entry) assigns.next();
        String user = (String) entry.getKey();
        Iterator iter = ((Set) entry.getValue()).iterator();
        while (iter.hasNext()) {
          String group = (String) iter.next();
          _userCache.assign(user, group);
        }
      }
      assigns = roleAssigns.entrySet().iterator();
      while (assigns.hasNext()) {
        Map.Entry entry = (Map.Entry) assigns.next();
        String role = (String) entry.getKey();
        Iterator iter = ((Set) entry.getValue()).iterator();
        while (iter.hasNext()) {
          String group = (String) iter.next();
          _userCache.addRoleToRole(role, group);
        }
      }
    } catch (ParserConfigurationException e) {
      _log.warn("Cannot parse user file: ", e);
    } catch (UserServiceException e) {
      _log.warn("Problem adding user or role from file: ", e);
    } catch (SAXException e) {
      _log.warn("Could not parse user file: ", e);
    } catch (IOException e) {
      _log.warn("Could not parse user file: ", e);
    }
  }

  private Map readMap(Element l) {
    Map map = new HashMap();
    NodeList nodes = l.getChildNodes();
    Set roles = new HashSet();
    for (int i = 0; i < nodes.getLength(); i++) {
      Node item = nodes.item(i);
      if (item instanceof Element) {
        String key = item.getNodeName();
        StringBuffer value = new StringBuffer();
        NodeList vals = item.getChildNodes();
        for (int j = 0; j < vals.getLength(); j++) {
          Node val = vals.item(j);
          if (val instanceof Text) {
            value.append(val.getNodeValue());
          }
        }
        String val = value.toString();
        if (ROLE_ASSIGNMENT.equals(key)) {
          roles.add(val);
        } else {
          map.put(key, val);
        }
      }
    }
    if (roles.size() != 0) {
      map.put(ROLE_ASSIGNMENT, roles);
    }
    return map;
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
        _userCache.disableUser((String) arr[0], ((Long) arr[0]).longValue());
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
        public boolean execute(Object obj) {
          return (obj instanceof CasRelay && 
                  ((CasRelay) obj).isTarget());
        }
      };


  private class MyServiceListener implements ServiceAvailableListener {
    private AgentIdentificationService _ais;
    private CommunityService     _cs;

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
        setDomain(_cs, _ais);
        getServiceBroker().releaseService(UserManagerPlugin.this, 
                                          CommunityService.class, _cs);
        getServiceBroker().releaseService(UserManagerPlugin.this, 
                                          AgentIdentificationService.class,
                                          _ais);
      }
    }
  }
}
