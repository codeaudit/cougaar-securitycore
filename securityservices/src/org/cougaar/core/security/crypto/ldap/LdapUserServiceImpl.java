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

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
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

import org.cougaar.core.security.services.crypto.LdapUserService;

public class LdapUserServiceImpl implements LdapUserService {

  private static final String PROP_BASE     =
    "org.cougaar.core.security.crypto.ldap.";
  public static final String PROP_URL      = PROP_BASE + "ldapurl";
  public static final String PROP_USER     = PROP_BASE + "user";
  public static final String PROP_PASSWORD = PROP_BASE + "password";
  public static final String PROP_USER_DN  = PROP_BASE + "user_dn";
  public static final String PROP_ROLE_DN  = PROP_BASE + "role_dn";
  public static final String PROP_URDN     = PROP_BASE + "user_rdn";
  public static final String PROP_RRDN     = PROP_BASE + "role_rdn";
  public static final String PROP_UOC      = PROP_BASE + "userClass";
  public static final String PROP_ROC      = PROP_BASE + "roleClass";
  public static final String PROP_RATTR    = PROP_BASE + "roleAttr";

  protected InitialDirContext _context;
  protected String            _url;
  protected String            _ldapUser;
  protected String            _ldapPwd;
  protected String            _userBase;
  protected String            _roleBase;
  protected String            _urdn;
  protected String            _rrdn;
  protected String            _uoc;
  protected String            _roc;
  protected String            _rattr;

  /**
   * Default constructor - initializes the LDAP connection using
   * environment variables
   */
  public LdapUserServiceImpl() throws NamingException {
    initializeProperties();

    Hashtable env = new Hashtable();
    setLdapEnvironment(env);

    _context = new InitialDirContext(env);
  }

  /**
   * Called during construction to initialize the following properties:
   * <ul>
   * <li>_url
   * <li>_ldapUser
   * <li>_ldapPwd
   * <li>_userBase
   * <li>_roleBase
   * <li>_urdn
   * <li>_rrdn
   * <li>_uoc
   * <li>_roc
   * <li>_rattr
   * </ul>
   * This implementation uses <code>System</code> properties using
   * the PROP_* class variables as keys.
   */
  protected void initializeProperties() {
    _ldapUser = System.getProperty(PROP_USER);
    _ldapPwd  = System.getProperty(PROP_PASSWORD);
    _url      = System.getProperty(PROP_URL, "ldaps:///");
    _userBase = System.getProperty(PROP_USER_DN,"dc=nai,dc=com");
    _roleBase = System.getProperty(PROP_ROLE_DN,"dc=roles,dc=nai,dc=com");
    _urdn     = System.getProperty(PROP_URDN, "cn");
    _rrdn     = System.getProperty(PROP_RRDN, "cn");
    _uoc      = System.getProperty(PROP_UOC, "person");
    _roc      = System.getProperty(PROP_ROC, "groupOfUniqueNames");
    _rattr    = System.getProperty(PROP_RATTR, "uniqueMember");
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

    String url = _url;
    if (url.startsWith("ldaps://")) {
      url = ldapsToLdap(url);
      env.put(Context.SECURITY_PROTOCOL,"ssl");
      env.put("java.naming.ldap.factory.socket", 
              "org.cougaar.core.security.ssl.KeyRingSSLFactory");
    }
    env.put(Context.PROVIDER_URL, url);
    
    if (_ldapUser != null) {
      env.put(Context.SECURITY_PRINCIPAL,_ldapUser);
    }
    if (_ldapPwd != null) {
      env.put(Context.SECURITY_CREDENTIALS,_ldapPwd);
    }
  }

  /**
   * Converts an ldaps://... url to ldap://..., including modification
   * of the port.
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
    return _urdn + "=" + uid + "," + _userBase;
  }

  private String rid2dn(String rid) {
    return _rrdn + "=" + rid + "," + _roleBase;
  }

  private SearchControls getControl(int maxResults) {
    return
      new SearchControls(SearchControls.SUBTREE_SCOPE, maxResults, 
                         0 /* no time limit */, null /* all attributes */,
                         true /* return the objects found */, 
                         true /* dereference links in the directory */);
  }

  public NamingEnumeration getUsers(String text, String field,
                                    int maxResults) throws NamingException {
    return _context.search(_userBase,
                           "(&(" + field + "=" + text + "),(objectClass=" +
                           _uoc + "))", getControl(maxResults));
  }

  public NamingEnumeration getUsers(String filter, int maxResults) throws NamingException {
    return _context.search(_userBase, "(&(" + filter + "),(objectClass=" +
                           _uoc + "))", getControl(maxResults));
  }

  public Attributes        getUser(String uid) throws NamingException {
    return _context.getAttributes(uid2dn(uid));
  }

  public void              editUser(String uid, ModificationItem[] mods) throws NamingException {
    _context.modifyAttributes(uid2dn(uid), mods);
  }

  public void              addUser(String uid, Attributes attrs) throws NamingException {
    attrs.put("objectClass", _uoc);
    _context.createSubcontext(uid2dn(uid), attrs);
  }

  public void              deleteUser(String uid) throws NamingException {
    NamingEnumeration ne = getRoles(uid);
    ArrayList roles = new ArrayList();
    while (ne.hasMore()) {
      Attributes attrs = (Attributes) ne.next();
      Attribute roleDN = attrs.get(_rrdn);
      roles.add(roleDN.get().toString());
    }
    Iterator i = roles.iterator();
    while (i.hasNext()) {
      String role = (String) i.next();
      unassign(uid, role);
    }
    _context.destroySubcontext(uid2dn(uid));
  }

  public NamingEnumeration getRoles(String uid) 
    throws NamingException {
    return _context.search(_roleBase,
                           "(&(" + _rattr + "=" + uid2dn(uid) +
                           "),(objectClass=" + _roc + "))",
                           getControl(0));
  }

  public NamingEnumeration getRoles(String searchText, int maxResults) 
    throws NamingException {
    return _context.search(_roleBase,
                           "(&(" + _rrdn + "=" + searchText +
                           "),(objectClass=" + _roc + "))", 
                           getControl(maxResults));
  }

  public NamingEnumeration getRoles(int maxResults) 
    throws NamingException {
    return _context.search(_roleBase,
                           "(objectClass=" + _roc + ")",
                           getControl(maxResults));
  }

  public Attributes        getRole(String rid) 
    throws NamingException {
    return _context.getAttributes(rid2dn(rid));
  }

  public void              assign(String uid, String rid) 
    throws NamingException {
    Attributes attrs = getRole(rid);
    Attribute  attr  = attrs.get(_rattr);
    NamingEnumeration ne = attr.getAll();
    String userDN = uid2dn(uid);
    while (ne.hasMore()) {
      String dn = ne.next().toString();
      if (dn != null && dn.equals(userDN)) {
        ne.close(); // abort, the user's already assigned
        return;
      }
    }
    // user's not there, so we should add her
    attrs = new BasicAttributes();
    attrs.put(_rattr, userDN);
    _context.modifyAttributes(rid2dn(rid), _context.ADD_ATTRIBUTE, attrs);
  }

  public void              unassign(String uid, String rid) 
    throws NamingException {
    BasicAttributes attrs = new BasicAttributes();
    attrs.put(_rattr, uid2dn(uid));
    try {
      _context.modifyAttributes(rid2dn(rid), _context.REMOVE_ATTRIBUTE, attrs);
    } catch (AttributeModificationException ex) {
      // probably wasn't there in the first place...
    }
  }

  public void              addRole(String rid) 
    throws NamingException {
    Attributes attrs = new BasicAttributes();
    attrs.put("objectClass", _roc);
    _context.createSubcontext(rid2dn(rid), attrs);
  }

  public void              deleteRole(String rid) 
    throws NamingException {
    _context.destroySubcontext(rid2dn(rid));
  }

}
