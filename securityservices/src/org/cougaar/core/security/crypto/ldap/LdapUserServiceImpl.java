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
import org.cougaar.planning.ldm.policy.RuleParameter;
import org.cougaar.core.security.policy.GuardRegistration;
import safe.enforcer.NodeEnforcer;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.core.security.policy.LdapUserServicePolicy;

public class LdapUserServiceImpl implements LdapUserService {

  public static final String PROP_URL      = "ldapurl";
  public static final String PROP_USER     = "user";
  public static final String PROP_PASSWORD = "password";
  public static final String PROP_USER_DN  = "user_dn";
  public static final String PROP_ROLE_DN  = "role_dn";
  public static final String PROP_URDN     = "user_rdn";
  public static final String PROP_RRDN     = "role_rdn";
  public static final String PROP_UOC      = "userClass";
  public static final String PROP_ROC      = "roleClass";
  public static final String PROP_RATTR    = "roleAttr";

  protected InitialDirContext _context     = null;
  protected String            _url         = "ldap:///";
  protected String            _ldapUser    = null;
  protected String            _ldapPwd     = null;
  protected String            _userBase    = "dc=cougaar,dc=org";
  protected String            _roleBase    = "dc=roles,dc=cougaar,dc=org";
  protected String            _urdn        = "uid";
  protected String            _rrdn        = "cn";
  protected String            _uoc         = "inetOrgPerson";
  protected String            _roc         = "groupOfUniqueNames";
  protected String            _rattr       = "uniqueMember";

  protected LdapUserServiceConfigurer _configurer;

  /**
   * Default constructor - initializes the LDAP connection using
   * the guard's policy. If no policy exists, there will be no
   * connection to the user database.
   */
  public LdapUserServiceImpl() {
    _configurer = new LdapUserServiceConfigurer();
  }

  /**
   * Default constructor - initializes the LDAP connection using
   * the guard's policy. If no policy exists, there will be no
   * connection to the user database.
   */
  public LdapUserServiceImpl(LdapUserServiceConfigurer configurer) {
    _configurer = configurer;
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

  public class LdapUserServiceConfigurer 
    extends GuardRegistration
    implements NodeEnforcer {
    public LdapUserServiceConfigurer() {
      super(LdapUserServicePolicy.class.getName(), "LdapUserService");
      try {
        registerEnforcer();
      } catch (Exception ex) {
        // FIXME: Shouldn't just let this drop, I think
        ex.printStackTrace();
      }
    }

    /**
     * Merges an existing policy with a new policy.
     * @param policy the new policy to be added
     */
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
      if (policy == null) {
        return;
      }

      if (debug) {
        System.out.println("LdapUserService: Received policy message");
        RuleParameter[] param = policy.getRuleParameters();
        for (int i = 0 ; i < param.length ; i++) {
          System.out.println("Rule: " + param[i].getName() +
                             " - " + param[i].getValue());
        }
      }

      boolean reset = false;

      // what is the policy change?
      RuleParameter[] param = policy.getRuleParameters();
      for (int i = 0; i < param.length; i++) {
        String name  = param[i].getName();
        String value = param[i].getValue().toString();
        if (PROP_URL.equals(name)) {
          reset = true;
          _url = value;
        } else if (PROP_USER.equals(name)) {
          reset = true;
          _ldapUser = value;
        } else if (PROP_PASSWORD.equals(name)) {
          reset = true;
          _ldapPwd = value;
        } else if (PROP_USER_DN.equals(name)) {
          _userBase = value;
        } else if (PROP_ROLE_DN.equals(name)) {
          _roleBase = value;
        } else if (PROP_URDN.equals(name)) {
          _urdn = value;
        } else if (PROP_RRDN.equals(name)) {
          _rrdn = value;
        } else if (PROP_UOC.equals(name)) {
          _uoc = value;
        } else if (PROP_ROC.equals(name)) {
          _roc = value;
        } else if (PROP_RATTR.equals(name)) {
          _rattr = value;
        } else {
          System.out.println("LdapUserServiceImpl: Don't know how to handle configuration parameter: " + name);
        }
      }
      if (reset) {
        synchronized (this) {
          if (_context != null) {
            try {
              _context.close();
            } catch (NamingException ne) {
              // ignore -- it's gone, anyway
            }
          }
          Hashtable env = new Hashtable();
          setLdapEnvironment(env);
          try {
            System.out.println("Starting Context: " + env);
            _context = new InitialDirContext(env);
          } catch (NamingException e) {
            System.out.println("LdapUserService: couldn't initialize connection to User LDAP database");
            e.printStackTrace();
          }
        }
      }
    }
  }
}
