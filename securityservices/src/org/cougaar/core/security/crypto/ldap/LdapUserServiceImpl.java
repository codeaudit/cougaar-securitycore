/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
package org.cougaar.core.security.crypto.ldap;

import java.util.Hashtable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Calendar;
import java.util.TimeZone;
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

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.planning.ldm.policy.RuleParameter;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.planning.ldm.policy.KeyRuleParameterEntry;
import org.cougaar.planning.ldm.policy.KeyRuleParameter;

// Cougaar security services
import org.cougaar.core.security.services.crypto.LdapUserService;
import org.cougaar.core.security.policy.GuardRegistration;
import org.cougaar.core.security.policy.LdapUserServicePolicy;
import org.cougaar.core.security.policy.SecurityPolicy;

// KAoS
import safe.enforcer.NodeEnforcer;

public class LdapUserServiceImpl implements LdapUserService {

  protected InitialDirContext _context     = null;
  protected LdapUserServicePolicy _policy  = new LdapUserServicePolicy();

  private static final int MAX_RETRIES = 3;
  private static final DateFormat DF=new SimpleDateFormat("yyyyMMddHHmmss'Z'");
  private static final TimeZone   GMT = TimeZone.getTimeZone("GMT");

  private ServiceBroker _serviceBroker;
  private ServiceBroker _nodeServiceBroker;
  private LoggingService _log;

  protected LdapUserServiceConfigurer _configurer;

  /**
   * Default constructor - initializes the LDAP connection using
   * the guard's policy. If no policy exists, there will be no
   * connection to the user database.
   */
  public LdapUserServiceImpl(ServiceBroker sb, ServiceBroker nsb) {
    _serviceBroker = sb;
    _nodeServiceBroker = nsb;
    _log = (LoggingService)
      _serviceBroker.getService(this, LoggingService.class, null);
    _configurer = new LdapUserServiceConfigurer(_nodeServiceBroker);
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
    return _policy.userRDN + "=" + uid + "," + _policy.userDN;
  }

  private String rid2dn(String rid) {
    return _policy.roleRDN + "=" + rid + "," + _policy.roleDN;
  }

  private SearchControls getControl(int maxResults) {
    return
      new SearchControls(SearchControls.SUBTREE_SCOPE, maxResults, 
                         0 /* no time limit */, null /* all attributes */,
                         true /* return the objects found */, 
                         true /* dereference links in the directory */);
  }

  private synchronized void checkContext() throws NamingException {
    if (_context == null) {
      Hashtable env = new Hashtable();
      setLdapEnvironment(env);
      _context = new InitialDirContext(env);
    }
  }

  private synchronized void resetContext() {
    if (_context != null) {
      try {
        _context.close();
      } catch (NamingException ne) {
        // ignore -- it's gone, anyway
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
    }
  }

  public void disableUser(String uid) throws NamingException {
    ModificationItem mods[] = new ModificationItem[1];
    mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
                                   new BasicAttribute(getEnableTimeAttribute()));
    editUser(uid, mods);
  }

  private static String toUTCString(long delayMillis) {
    Calendar time = Calendar.getInstance(GMT);
    time.add(time.MINUTE, (int) (delayMillis/60000));
    time.add(time.MILLISECOND, (int) (delayMillis % 60000));
    return DF.format(time.getTime());
  }

  public void disableUser(String uid, long milliseconds) 
    throws NamingException {
    ModificationItem mods[] = new ModificationItem[1];
    String enableTime = toUTCString(milliseconds);
    mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                                   new BasicAttribute(getEnableTimeAttribute(),
                                                      enableTime));
    editUser(uid, mods);
  }

  public void enableUser(String uid) 
    throws NamingException {
    ModificationItem mods[] = new ModificationItem[1];
    String enableTime = toUTCString(-600000);
    mods[0] = 
      new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                           new BasicAttribute(getEnableTimeAttribute(),
                                              enableTime));
    editUser(uid, mods);
  }

  public NamingEnumeration getUsers(String text, String field,
                                    int maxResults) throws NamingException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        return _context.search(_policy.userDN,
                               "(&(" + field + "=" + text + "),(objectClass=" +
                               _policy.userObjectClass[0] + "))", 
                               getControl(maxResults));
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else if (ne instanceof NameNotFoundException) createUserBase();
        else throw ne;
      }
    }
    return null;  // it will never get here
  }

  public NamingEnumeration getUsers(String filter, int maxResults) throws NamingException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        return _context.search(_policy.userDN,
                               "(&(" + filter + "),(objectClass=" +
                               _policy.userObjectClass[0] + "))",
                               getControl(maxResults));
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else if (ne instanceof NameNotFoundException) createUserBase();
        else throw ne;
      }
    }
    return null; // it will never get here
  }

  public Attributes        getUser(String uid) throws NamingException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        return _context.getAttributes(uid2dn(uid));
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else throw ne;
      }
    }
    return null; // it will never get here
  }

  public void              editUser(String uid, ModificationItem[] mods) throws NamingException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        _context.modifyAttributes(uid2dn(uid), mods);
        return;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else throw ne;
      }
    }
  }

  public void              addUser(String uid, Attributes attrs)
    throws NamingException {
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
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else throw ne;
      }
    }
  }

  public void              deleteUser(String uid) throws NamingException {
    NamingEnumeration ne = getRoles(uid);
    ArrayList roles = new ArrayList();
    while (ne.hasMore()) {
      SearchResult res = (SearchResult) ne.next();
      Attributes attrs = (Attributes) res.getAttributes();
      Attribute roleDN = attrs.get(_policy.roleRDN);
      roles.add(roleDN.get().toString());
    }
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
        if (tryCount + 1 == MAX_RETRIES) throw nex;
        if (nex instanceof CommunicationException) resetContext();
        else throw nex;
      }
    }
  }

  public NamingEnumeration getRoles(String uid) 
    throws NamingException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        return _context.search(_policy.roleDN,
                               "(&(" + _policy.roleAttr + "=" + uid2dn(uid) +
                               "),(objectClass=" + 
                               _policy.roleObjectClass[0] + "))",
                               getControl(0));
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else if (ne instanceof NameNotFoundException) createRoleBase();
        else throw ne;
      }
    }
    return null; // it will never get here
  }

  public NamingEnumeration getRoles(String searchText, String field, 
                                    int maxResults) 
    throws NamingException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        return _context.search(_policy.roleDN,
                               "(&(" + field + "=" + searchText +
                               "),(objectClass=" +
                               _policy.roleObjectClass[0] + "))", 
                               getControl(maxResults));
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else if (ne instanceof NameNotFoundException) createRoleBase();
        else throw ne;
      }
    }
    return null; // it will never get here
  }

  public NamingEnumeration getRoles(int maxResults) 
    throws NamingException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        return _context.search(_policy.roleDN,
                               "(objectClass=" + 
                               _policy.roleObjectClass[0] + ")",
                               getControl(maxResults));
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else if (ne instanceof NameNotFoundException) createRoleBase();
        else throw ne;
      }
    }
    return null; // it will never get here
  }

  public Attributes        getRole(String rid) 
    throws NamingException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        return _context.getAttributes(rid2dn(rid));
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else throw ne;
      }
    }
    return null; // it will never get here
  }

  public void              assign(String uid, String rid) 
    throws NamingException {
    Attributes attrs = getRole(rid);
    String userDN = uid2dn(uid);

    attrs = new BasicAttributes();
    attrs.put(_policy.roleAttr, userDN);
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        _context.modifyAttributes(rid2dn(rid), _context.ADD_ATTRIBUTE, attrs);
        return;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else throw ne;
      }
    }
  }

  public void              unassign(String uid, String rid) 
    throws NamingException {
    BasicAttributes attrs = new BasicAttributes();
    attrs.put(_policy.roleAttr, uid2dn(uid));
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
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else throw ne;
      }
    }
  }

  public void              addRole(String rid) throws NamingException {
    BasicAttributes attrs = new BasicAttributes();
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
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else throw ne;
      }
    }
  }

  public void              addRole(String rid, Attributes attrs) 
    throws NamingException {
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
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else throw ne;
      }
    }
  }

  public void              editRole(String rid, ModificationItem[] mods)
    throws NamingException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        _context.modifyAttributes(rid2dn(rid), mods);
        return;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else throw ne;
      }
    }
  }

  public void              deleteRole(String rid) 
    throws NamingException {
    checkContext();
    for (int tryCount = 0; tryCount < MAX_RETRIES; tryCount++) {
      try {
        _context.destroySubcontext(rid2dn(rid));
        return;
      } catch (NamingException ne) {
        if (tryCount + 1 == MAX_RETRIES) throw ne;
        if (ne instanceof CommunicationException) resetContext();
        else throw ne;
      }
    }
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

  public class LdapUserServiceConfigurer 
    extends GuardRegistration
    implements NodeEnforcer {
    public LdapUserServiceConfigurer(ServiceBroker sb) {
      super(LdapUserServicePolicy.class.getName(), "LdapUserService",
	    sb);
      try {
        registerEnforcer();
      } catch (Exception ex) {
        // FIXME: Shouldn't just let this drop, I think
        ex.printStackTrace();
      }
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

      if (_log.isDebugEnabled()) {
        _log.debug("Received policy message");
        _log.debug(policy.toString());
      }

      _policy = (LdapUserServicePolicy) policy;

      resetContext();
    }
  }
}
