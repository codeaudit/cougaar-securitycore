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

import java.util.*;
import java.lang.ref.*;
import java.net.SocketException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.CommunicationException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.directory.AttributeModificationException;

import EDU.oswego.cs.dl.util.concurrent.Semaphore;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.planning.ldm.policy.RuleParameter;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.planning.ldm.policy.KeyRuleParameterEntry;
import org.cougaar.planning.ldm.policy.KeyRuleParameter;

// Cougaar security services
import org.cougaar.core.security.services.acl.UserService;
import org.cougaar.core.security.services.acl.UserServiceException;
import org.cougaar.core.security.policy.GuardRegistration;
import org.cougaar.core.security.policy.LdapUserServicePolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.Entity;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceAvailableEvent;

// KAoS
import safe.enforcer.NodeEnforcer;

public class LdapUserServiceImpl implements UserService {

  protected InitialDirContext _context     = null;

  private static final int MAX_RETRIES = 3;
  private static final DateFormat DF=new SimpleDateFormat("yyyyMMddHHmmss'Z'");
  private static final TimeZone   GMT = TimeZone.getTimeZone("GMT");

  private ServiceBroker _serviceBroker;
  private LoggingService _log;
  private String _defaultDomain;
  private final String[] USER_ATTRIBUTES = new String[] {
    "uid", "userPassword", "cn", "mail", "cougaarAcctEnableTime", 
    "cougaarAuthReq", "certIsSpecial", "sn", "givenName"
  };

  private final String[] ROLE_ATTRIBUTES = new String[] {
    "cn", "description"
  };
  private final String ROLE_LIST_ATTR = "roles";

  private static LdapUserServiceConfigurer _configurer;
  private static LdapUserServicePolicy _policy  = new LdapUserServicePolicy();

  public static void setRootServiceBroker(ServiceBroker root) {
    _configurer = new LdapUserServiceConfigurer(root);
  }

  /**
   * Default constructor - initializes the LDAP connection using
   * the guard's policy. If no policy exists, there will be no
   * connection to the user database.
   */
  public LdapUserServiceImpl(ServiceBroker sb, MessageAddress agent) {
    _serviceBroker = sb;
    _log = (LoggingService)
      _serviceBroker.getService(this, LoggingService.class, null);
    setDefaultDomain(sb, agent);
  }

  /**
   * Adds the necessary environment variables to env to allow
   * JNDI initialization.
   *
   * @param env A <code>Hashtable</code> that is to hold JNDI initialization
   *            environment variables. This function should modify env.
   * @see InitialDirContext
   */
  protected void setLdapEnvironment(Hashtable env) {
    env.put(Context.INITIAL_CONTEXT_FACTORY, 
            "com.sun.jndi.ldap.LdapCtxFactory");

    String url = _policy.ldapUrl;
    if (url.startsWith("ldaps://")) {
      url = ldapsToLdap(url);
      env.put(Context.SECURITY_PROTOCOL,"ssl");
      env.put("java.naming.ldap.factory.socket", 
              "org.cougaar.core.security.ssl.KeyRingSSLFactory");
    }
    env.put(Context.PROVIDER_URL, url);
    
    if (_policy.ldapUser != null) {
      env.put(Context.SECURITY_PRINCIPAL,_policy.ldapUser);
    }
    if (_policy.ldapPassword != null) {
      env.put(Context.SECURITY_CREDENTIALS,_policy.ldapPassword);
    }
  }

  private void setDefaultDomain(ServiceBroker sb, MessageAddress address) {
    String agent = address.getAddress();
    CommunityService cs = (CommunityService)
      sb.getService(this, CommunityService.class, null);
    if (cs == null) {
      _serviceBroker.addServiceListener(new CommunityServiceListener(agent));
    } else {
      setDefaultDomain(cs, agent);
    }

  }

  private class Status {
    public Object value;
  }

  private void setDefaultDomain(CommunityService cs, String agent) {

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
    cs.searchCommunity(null, filter, true,
		       Community.COMMUNITIES_ONLY, crl);
    try {
      s.acquire();
    } catch (InterruptedException ie) {
      _log.error("Error in searchByCommunity:", ie);
    }

    Collection communities=(Set)status.value;
    if (!communities.isEmpty()) {
      Community c = (Community) communities.iterator().next();
      _defaultDomain = c.getName();
    }
  }

  /**
   * Converts an "ldaps://..." url to "ldap://..." including modification
   * of the default port.
   *
   * @param url String containg the ldaps url. It must begin with "ldaps://".
   */
  protected static String ldapsToLdap(String url) {
    int colonIndex = url.indexOf(":",8);
    int slashIndex = url.indexOf("/",8);
    String host;
    if (slashIndex == -1) slashIndex = url.length();
    if (colonIndex == -1 || colonIndex > slashIndex) {
      // there is no default port -- change the default
      // port to 636 for ldaps
      if (slashIndex == 0) {
        // there is no host either -- use 0.0.0.0 as host
        host = "0.0.0.0";
      } else {
        host = url.substring(8,slashIndex);
      }
      url = "ldap://" + host + ":636" + 
        url.substring(slashIndex);
    } else {
      url = "ldap://" + url.substring(8);
    }
    return url;
  }

  private String uid2dn(String uid) {
    int index = uid.indexOf("\\");
    String dc = ",";
    if (index > 0) {
      dc = ",dc=" + uid.substring(0,index) + ",";
      uid = uid.substring(index+1);
    }
    return _policy.userRDN + "=" + uid + dc + _policy.userDN;
  }

  private String rid2dn(String rid) {
    int index = rid.indexOf("\\");
    String dc = ",";
    if (index > 0) {
      dc = ",dc=" + rid.substring(0,index) + ",";
      rid = rid.substring(index+1);
    }
    return _policy.roleRDN + "=" + rid + dc + _policy.roleDN;
  }

  private static String dn2id(String dn, String base) {
    dn = dn.substring(0, dn.length() - base.length() - 1);
    int indexCm = dn.indexOf(",");
    String dc = "";
    if (indexCm > 0) {
      int indexEq = dn.indexOf("=", indexCm);
      dc = dn.substring(indexEq + 1) + "\\";
      dn = dn.substring(0,indexCm);
    } else {
      indexCm = dn.length();
    }
    int indexEq = dn.indexOf("=");
    return dc + dn.substring(indexEq+1, indexCm);
  }

  private String dn2rid(String dn) {
    return dn2id(dn, _policy.roleDN);
  }

  private String dn2uid(String dn) {
    return dn2id(dn, _policy.userDN);
  }

  private Set dn2rid(Set ids) {
    Iterator iter = ids.iterator();
    Set newSet = new HashSet();
    while (iter.hasNext()) {
      String id = (String) iter.next();
      newSet.add(dn2id(id, _policy.roleDN));
    }
    return newSet;
  }

  private SearchControls getControl(int maxResults) {
    return
      new SearchControls(SearchControls.SUBTREE_SCOPE, maxResults, 
                         0 /* no time limit */, null /* all attributes */,
                         true /* return the objects found */, 
                         true /* dereference links in the directory */);
  }

  private SearchControls getControl(int maxResults, String attrs[]) {
    return
      new SearchControls(SearchControls.SUBTREE_SCOPE, maxResults, 
                         0 /* no time limit */, attrs,
                         true /* return the objects found */, 
                         true /* dereference links in the directory */);
  }

  private synchronized void checkContext() throws UserServiceException {
    try {
      if (_context == null) {
        Hashtable env = new Hashtable();
        setLdapEnvironment(env);
        _context = new InitialDirContext(env);
      }
    } catch (NamingException e) {
      throw new UserServiceException(e);
    }
  }

  private synchronized void resetContext() {
    if (_context != null) {
      try {
        _context.close();
      } catch (NamingException ne) {
        // ignore -- it's gone, anyway
        if (_log.isDebugEnabled()) {
          _log.debug("Ignore exception, it's gone anyway", ne);
        }
      }
    }
    _context = null;
    Hashtable env = new Hashtable();
    setLdapEnvironment(env);
    try {
      _context = new InitialDirContext(env);
    } catch (NamingException e) {
      _log.error("Couldn't initialize connection to User LDAP database. URL is "
		 + env.get(Context.PROVIDER_URL));
      if (_log.isDebugEnabled()) {
        _log.debug("Exception caught", e);
      }
    }
  }

  private void createUserBase() {
    BasicAttributes attrs = new BasicAttributes();
    attrs.put("objectClass","dcObject");
    int commaIndex = _policy.userDN.indexOf(",");
    String dcComponent;
    if (commaIndex != -1) {
      dcComponent = _policy.userDN.substring(0,commaIndex);
    } else {
      dcComponent = _policy.userDN;
    }
    int equalIndex = dcComponent.indexOf("=");
    if (equalIndex == -1) {
      // real problem here!
      throw new IllegalStateException("Can't create user base -- the user base specified (" + _policy.userDN + ") is not a dcObject");
    } 
    dcComponent = dcComponent.substring(equalIndex + 1);

    attrs.put("dc", dcComponent);
    try {
      _context.createSubcontext(_policy.userDN, attrs);
    } catch (NamingException ne) {
      // ignore it... this is in the middle of another call, anyway
      if (_log.isDebugEnabled()) {
        _log.debug("Ignore exception, this is the middle of another call anyway", ne);
      }
    }
  }

  private void createRoleBase() {
    BasicAttributes attrs = new BasicAttributes();
    attrs.put("objectClass","dcObject");
    int commaIndex = _policy.roleDN.indexOf(",");
    String dcComponent;
    if (commaIndex != -1) {
      dcComponent = _policy.roleDN.substring(0,commaIndex);
    } else {
      dcComponent = _policy.roleDN;
    }
    int equalIndex = dcComponent.indexOf("=");
    if (equalIndex == -1) {
      // real problem here!
      throw new IllegalStateException("Can't create role base -- the role base specified (" + _policy.roleDN + ") is not a dcObject");
    } 
    dcComponent = dcComponent.substring(equalIndex + 1);

    attrs.put("dc", dcComponent);
    try {
      _context.createSubcontext(_policy.roleDN, attrs);
    } catch (NamingException ne) {
      // ignore it... this is in the middle of another call, anyway
      if (_log.isDebugEnabled()) {
        _log.debug("Ignore exception, this is the middle of another call anyway", ne);
      }
    }
  }

  public void disableUser(String uid) throws UserServiceException {
    Set set = new HashSet();
    set.add(getEnableTimeAttribute());
    editUser(uid, null, null, set);
  }

  public void lockCertificate(String uid) throws UserServiceException {
    Map map = new HashMap();
    map.put(getCertOkAttribute(), "FALSE");
    editUser(uid, null, map, null);
  }

  public void unlockCertificate(String uid) throws UserServiceException {
    Map map = new HashMap();
    map.put(getCertOkAttribute(), "TRUE");
    editUser(uid, null, map, null);
  }

  private static String toUTCString(long delayMillis) {
    Calendar time = Calendar.getInstance(GMT);
    time.add(time.MINUTE, (int) (delayMillis/60000));
    time.add(time.MILLISECOND, (int) (delayMillis % 60000));
    return DF.format(time.getTime());
  }

  public void disableUser(String uid, long milliseconds) 
    throws UserServiceException {
    String enableTime = toUTCString(milliseconds);
    Map map = new HashMap();
    map.put(getEnableTimeAttribute(), enableTime);
    editUser(uid, null, map, null);
  }

  public void enableUser(String uid) 
    throws UserServiceException {
    String enableTime = toUTCString(-600000);
    Map map = new HashMap();
    map.put(getEnableTimeAttribute(), enableTime);
    editUser(uid, null, map, null);
  }

  private Set searchUsers(String domain, String filter, int maxResults) 
    throws UserServiceException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        String dn;
        String base = "";
        if (domain == null) {
          dn = _policy.userDN;
        } else {
          dn = "dc=" + domain + "," + _policy.userDN;
          base = domain + "\\";
        }
        NamingEnumeration en = 
          _context.search(dn, filter,
                          getControl(maxResults, new String[]{_policy.userRDN}));
        Set set = new HashSet();
        while (en.hasMore()) {
          SearchResult sr = (SearchResult) en.next();
          Attributes attrs = sr.getAttributes();
          Attribute uidAttr = attrs.get(_policy.userRDN);
          if (uidAttr != null && uidAttr.size() > 0) {
            set.add(base + uidAttr.get());
          }
        }
        return set;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else if (ne instanceof NameNotFoundException) createUserBase();
        else throw new UserServiceException(ne);
      }
    }
    return null;  // it will never get here
  }

  public Set getUsers(String domain, String text, String field,
                      int maxResults) throws UserServiceException {
    return searchUsers(domain, "(&(" + field + "=" + text + "),(objectClass=" +
                       _policy.userObjectClass[0] + "))", maxResults);
  }

  private Map createMap(Attributes attrs, String[] keys, String id) 
    throws NamingException {
    if (attrs == null) {
      return null;
    }

    Map map = new HashMap();
    for (int i = 0; i < keys.length; i++) {
      Attribute attr = attrs.get(keys[i]);
      if (attr != null && attr.size() != 0) {
        Object val = attr.get();
        if (i == 0) { // id attribute needs to be adjusted
          val = id; // just use the one used in the search
        }
        map.put(keys[i], val);
      }
    }
    return map;
  }

  public Map getUser(String uid) throws UserServiceException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        Attributes attrs = _context.getAttributes(uid2dn(uid));
        if (attrs == null) {
          return null;
        }
        Map rv = createMap(attrs, USER_ATTRIBUTES, uid);
        Set roles = getRoles(uid);
        if (roles != null) {
          rv.put(ROLE_LIST_ATTR, roles);
        }
        return rv;
      } catch (NameNotFoundException ne) {
        return null; // no such user
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else throw new UserServiceException(ne);
      }
    }
    return null; // it will never get here
  }

  private static ModificationItem[] createMods(Map added, Map edited, 
                                               Set deleted) {
    ArrayList mods = new ArrayList();
    Iterator iter;
    if (added != null) {
      iter = added.entrySet().iterator();
      while (iter.hasNext()) {
        Map.Entry entry = (Map.Entry) iter.next();
        Object key = entry.getKey();
        Object val = entry.getValue();
        Attribute attr = new BasicAttribute((String) key, val);
        mods.add(new ModificationItem(DirContext.ADD_ATTRIBUTE, attr));
      }
    }
    if (edited != null) {
      // yeah, I know copy and paste, but this is easier
      iter = edited.entrySet().iterator();
      while (iter.hasNext()) {
        Map.Entry entry = (Map.Entry) iter.next();
        Object key = entry.getKey();
        Object val = entry.getValue();
        Attribute attr = new BasicAttribute((String) key, val);
        mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, attr));
      }
    }
    if (deleted != null) {
      iter = deleted.iterator();
      while (iter.hasNext()) {
        Attribute attr = new BasicAttribute((String) iter.next());
        mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, attr));
      }
    }
    return (ModificationItem[]) 
      mods.toArray(new ModificationItem[mods.size()]);
  }

  public void editUser(String uid, Map added, Map edited, Set deleted)
    throws UserServiceException {
    checkContext();
    ModificationItem mods[] = createMods(added, edited, deleted);
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        _context.modifyAttributes(uid2dn(uid), mods);
        return;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else throw new UserServiceException(ne);
      }
    }
  }

  private static Attributes createAttributes(Map attrs) {
    BasicAttributes battrs = new BasicAttributes();
    if (attrs != null) {
      Iterator iter = attrs.entrySet().iterator();
      while (iter.hasNext()) {
        Map.Entry entry = (Map.Entry) iter.next();
        battrs.put((String)entry.getKey(), entry.getValue());
      }
    }
    return battrs;
  }

  public void addUser(String uid, Map map)
    throws UserServiceException {
    if (!map.containsKey("sn")) {
      map.put("sn", uid);
    }
    if (!map.containsKey("cn")) {
      map.put("cn", uid);
    }
    Attributes attrs = createAttributes(map);
    Attribute oc = new BasicAttribute("objectClass");
    for (int i = 0; i < _policy.userObjectClass.length; i++) {
      oc.add(_policy.userObjectClass[i]);
    }
    attrs.put(oc);
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        _context.createSubcontext(uid2dn(uid), attrs);
        return;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else throw new UserServiceException(ne);
      }
    }
  }

  public void deleteUser(String uid) throws UserServiceException {
    Set roles = getRoles(uid);
    Iterator i = roles.iterator();
    while (i.hasNext()) {
      String role = (String) i.next();
      unassign(uid, role);
    }
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        _context.destroySubcontext(uid2dn(uid));
        return;
      } catch (NamingException nex) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(nex);
        if (nex instanceof CommunicationException) resetContext();
        else throw new UserServiceException(nex);
      }
    }
  }

  private Set searchRoles(String domain, String filter, int maxResults) 
    throws UserServiceException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        String dn;
        String base = "";
        if (domain == null) {
          dn = _policy.roleDN;
        } else {
          dn = "dc=" + domain + "," + _policy.roleDN;
          base = domain + "\\";
        }
        NamingEnumeration en = 
          _context.search(dn, filter,
                          getControl(0, new String[] {_policy.roleRDN}));
        Set set = new TreeSet();
        while (en.hasMore()) {
          SearchResult sr = (SearchResult) en.next();
          Attributes attrs = sr.getAttributes();
          Attribute ridAttr = attrs.get(_policy.roleRDN);
          if (ridAttr != null && ridAttr.size() > 0) {
            set.add(base + ridAttr.get());
          }
        }
        return set;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else if (ne instanceof NameNotFoundException) createUserBase();
        else throw new UserServiceException(ne);
      }
    }
    return null;  // it will never get here
  }

  public Set getRoles(String uid) 
    throws UserServiceException {
    return searchRoles(null,
                       "(&(" + _policy.roleAttr + "=" + uid2dn(uid) +
                       "),(objectClass=" + 
                       _policy.roleObjectClass[0] + "))", 0);
  }

  public Set getRoles(String domain, String searchText, 
                      String field, int maxResults) 
    throws UserServiceException {
    return searchRoles(domain, "(&(" + field + "=" + searchText +
                       "),(objectClass=" +
                       _policy.roleObjectClass[0] + "))", maxResults);
  }

  public Set getRoles(String domain, int maxResults) 
    throws UserServiceException {
    return searchRoles(domain, "(objectClass=" + 
                       _policy.roleObjectClass[0] + ")", maxResults);
  }

  public Map getRole(String rid) throws UserServiceException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        Map rv = createMap(_context.getAttributes(rid2dn(rid)), 
                           ROLE_ATTRIBUTES, rid);
        if (rv == null) {
          return null;
        }
        Set roles = getContainedRoles(rid);
        if (roles != null) {
          rv.put(ROLE_LIST_ATTR, roles);
        }
        return rv;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else throw new UserServiceException(ne);
      }
    }
    return null; // it will never get here
  }

  private void assignToRole(String rid, String dn) 
    throws UserServiceException {
    checkContext();
    String ridDN = rid2dn(rid);
    // ensure that the value isn't there already
    for (int tryCount = 0; tryCount < MAX_RETRIES; 
         tryCount++) {
      try {
        Attributes attrs = _context.getAttributes(ridDN);
        if (attrs == null) {
          throw new UserServiceException("role does not exist");
        }
        Set values = new HashSet();
        Attribute attr = attrs.get(_policy.roleAttr);
        if (attr != null) {
          for (int i = 0; i < attr.size(); i++) {
            values.add(attr.get(i));
          }
        }
        if (values.contains(dn)) {
          return; // already there
        }
        attr = new BasicAttribute(_policy.roleAttr, dn);
        ModificationItem mods[] = new ModificationItem[] { 
          new ModificationItem(DirContext.ADD_ATTRIBUTE, attr)
        };
        _context.modifyAttributes(ridDN, mods);
        return;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else throw new UserServiceException(ne);
      }
    }
  }

  public void assign(String uid, String rid) 
    throws UserServiceException {
    assignToRole(rid, uid2dn(uid));
  }

  public void addRoleToRole(String container, String containee) 
    throws UserServiceException {
    Set roles = expandRoles(new String[] {containee});
    if (roles.contains(container)) {
      throw new UserServiceException("Attempting circular role hierarchy");
    }
    
    // no circular reference, now add the role to the role
    assignToRole(container, rid2dn(containee));
  }

  private void unassignToRole(String rid, String dn) 
    throws UserServiceException {
    BasicAttributes attrs = new BasicAttributes();
    attrs.put(_policy.roleAttr, dn);
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        _context.modifyAttributes(rid2dn(rid), _context.REMOVE_ATTRIBUTE, 
                                  attrs);
        return;
      } catch (AttributeModificationException ex) {
        // probably wasn't there in the first place...
        return;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else throw new UserServiceException(ne);
      }
    }
  }

  public void unassign(String uid, String rid) throws UserServiceException {
    unassignToRole(rid, uid2dn(uid));
  }

  public void removeRoleFromRole(String container, String containee) 
    throws UserServiceException {
    unassignToRole(container, rid2dn(containee));
  }

  public void addRole(String rid) throws UserServiceException {
    addRole(rid, null);
  }

  private void expandRoles(String rid, Set roles) throws UserServiceException {
    if (!roles.contains(rid)) {
      Set newRoles = getContainedRids(rid);
      Iterator iter = newRoles.iterator();
      while (iter.hasNext()) {
        String ridNext = (String) iter.next();
        if (!roles.contains(ridNext)) {
          roles.add(ridNext);
          expandRoles(ridNext, roles);
        }
      }
    }
  }

  public Set expandRoles(String rids[]) throws UserServiceException {
    HashSet roles = new HashSet();
    for (int i = 0; i < rids.length; i++) {
      expandRoles(rid2dn(rids[i]), roles);
    }
    return dn2rid(roles);
  }

  private Set getContainedRids(String rid) throws UserServiceException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        Attributes attrs = _context.getAttributes(rid);
        if (attrs == null) {
          return null;
        }

        Set roles = new HashSet();
        Attribute attr = attrs.get(_policy.roleAttr);
        if (attr != null) {
          for (int i = 0; i < attr.size(); i++) {
            String val = (String) attr.get(i);
            if (val.endsWith("," + _policy.roleDN)) {
              roles.add(dn2rid(val));
            }
          }
        }
        return roles;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else throw new UserServiceException(ne);
      }
    }
    return null; // it will never get here
  }

  public Set getUsersInRole(String rid)  throws UserServiceException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        Attributes attrs = _context.getAttributes(rid2dn(rid));
        if (attrs == null) {
          return null;
        }

        Set users = new HashSet();
        Attribute attr = attrs.get(_policy.roleAttr);
        if (attr != null) {
          for (int i = 0; i < attr.size(); i++) {
            String val = (String) attr.get(i);
            if (val.endsWith("," + _policy.userDN)) {
              users.add(dn2uid(val));
            }
          }
        }
        return users;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else throw new UserServiceException(ne);
      }
    }
    return null; // it will never get here
  }

  public Set getContainedRoles(String rid) throws UserServiceException {
    return getContainedRids(rid2dn(rid));
  }

  public void addRole(String rid, Map map) throws UserServiceException {
    Attributes attrs = createAttributes(map);
    Attribute oc = new BasicAttribute("objectClass");
    for (int i = 0; i < _policy.roleObjectClass.length; i++) {
      oc.add(_policy.roleObjectClass[i]);
    }
    attrs.put(oc);
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        _context.createSubcontext(rid2dn(rid), attrs);
        return;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else throw new UserServiceException(ne);
      }
    }
  }

  public void editRole(String rid, Map added, Map edited, Set deleted) 
    throws UserServiceException {
    checkContext();
    ModificationItem[] mods = createMods(added, edited, deleted);
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        _context.modifyAttributes(rid2dn(rid), mods);
        return;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else throw new UserServiceException(ne);
      }
    }
  }

  public void deleteRole(String rid) throws UserServiceException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        _context.destroySubcontext(rid2dn(rid));
        return;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw new UserServiceException(ne);
        if (ne instanceof CommunicationException) resetContext();
        else throw new UserServiceException(ne);
      }
    }
  }

  public String getRoleListAttribute() {
    return ROLE_LIST_ATTR;
  }

  public String  getPasswordAttribute() {
    return _policy.passwordAttr;
  }

  public String getUserRoleAttribute() {
    return _policy.roleAttr;
  }

  public String getAuthFieldsAttribute() {
    return _policy.authAttr;
  }

  public String getEnableTimeAttribute() {
    return _policy.enableAttr;
  }

  public String getUserIDAttribute() {
    return _policy.userRDN;
  }

  public String getRoleIDAttribute() {
    return _policy.roleRDN;
  }

  public String getCertOkAttribute() {
    return _policy.certOkAttr;
  }

  public String getDefaultDomain() {
    return _defaultDomain;
  }

  private void setUserAttributes() {
    USER_ATTRIBUTES[0] = getUserIDAttribute();
    USER_ATTRIBUTES[1] = getPasswordAttribute();
    USER_ATTRIBUTES[2] = "cn";
    USER_ATTRIBUTES[3] = "sn";
    USER_ATTRIBUTES[4] = "givenName";
    USER_ATTRIBUTES[5] = "mail";
    USER_ATTRIBUTES[6] = getEnableTimeAttribute();
    USER_ATTRIBUTES[7] = getAuthFieldsAttribute();
    USER_ATTRIBUTES[8] = getCertOkAttribute();
  }

  private void setRoleAttributes() {
    ROLE_ATTRIBUTES[0] = getRoleIDAttribute();
    ROLE_ATTRIBUTES[1] = "description";
  }

  private static class LdapUserServiceConfigurer 
    extends GuardRegistration implements NodeEnforcer {
    private LoggingService log;
    private LinkedList _callBacks = new LinkedList();

    public LdapUserServiceConfigurer(ServiceBroker sb) {
      super(LdapUserServicePolicy.class.getName(), "LdapUserService",
	    sb);
      try {
        log = (LoggingService) sb.getService(this, LoggingService.class, null);
        registerEnforcer();
      } catch (Exception ex) {
        // FIXME: Shouldn't just let this drop, I think
	log.warn("Unable to register LdapUserServiceConfigurer policy enforcer", ex);
      }
    }

    public void addService(LdapUserServiceImpl service) {
      _callBacks.add(new WeakReference(service));
    }

    public void receivePolicyMessage(Policy policy,
                                     String policyID,
                                     String policyName,
                                     String policyDescription,
                                     String policyScope,
                                     String policySubjectID,
                                     String policySubjectName,
                                     String policyTargetID,
                                     String policyTargetName,
                                     String policyType) {
      log.warn("receivePolicyMessage(Policy,... ) should not be called");
    }

    /**
     * Merges an existing policy with a new policy.
     * @param policy the new policy to be added
     */
    public void receivePolicyMessage(SecurityPolicy policy,
                                     String policyID,
                                     String policyName,
                                     String policyDescription,
                                     String policyScope,
                                     String policySubjectID,
                                     String policySubjectName,
                                     String policyTargetID,
                                     String policyTargetName,
                                     String policyType) {
      if (policy == null || !(policy instanceof LdapUserServicePolicy)) {
        return;
      }

      if (log.isDebugEnabled()) {
        log.debug("Received policy message");
        log.debug(policy.toString());
      }

      _policy = (LdapUserServicePolicy) policy;
      Iterator iter = _callBacks.iterator();
      while (iter.hasNext()) {
        Reference ref = (Reference) iter.next();
        LdapUserServiceImpl ldap = (LdapUserServiceImpl) ref.get();
        if (ldap == null) {
          iter.remove();
        } else {
          ldap.setUserAttributes();
          ldap.setRoleAttributes();
          ldap.resetContext();
        }
      }
    }
  }


  private class CommunityServiceListener implements ServiceAvailableListener {
    private String _agent;

    public CommunityServiceListener(String agent) {
      _agent = agent;
    }

    public void serviceAvailable(ServiceAvailableEvent ae) {
      if (ae.getService().equals(CommunityService.class)) {
        CommunityService cs = (CommunityService) ae.getServiceBroker().
           getService(this, CommunityService.class, null);
        if (cs != null) {
          ae.getServiceBroker().removeServiceListener(this);
          setDefaultDomain(cs, _agent);
          ae.getServiceBroker().releaseService(this, CommunityService.class,
                                               cs);
        }
      }
    }
  }
}
