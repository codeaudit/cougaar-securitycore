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

import org.cougaar.core.security.services.crypto.LdapUserService;
import org.cougaar.planning.ldm.policy.RuleParameter;
import org.cougaar.core.security.policy.GuardRegistration;
import safe.enforcer.NodeEnforcer;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.core.security.policy.LdapUserServicePolicy;
import org.cougaar.planning.ldm.policy.KeyRuleParameterEntry;
import org.cougaar.planning.ldm.policy.KeyRuleParameter;

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
  public static final String PROP_PWDATTR  = "passwordAttr";
  public static final String PROP_AUTHATTR = "authFieldsAttr";
  public static final String PROP_ETATTR   = "enableTimeAttr";

  protected InitialDirContext _context     = null;
  protected String            _url         = "ldap:///";
  protected String            _ldapUser    = null;
  protected String            _ldapPwd     = null;
  protected String            _userBase    = "dc=cougaar,dc=org";
  protected String            _roleBase    = "dc=roles,dc=cougaar,dc=org";
  protected String            _urdn        = "uid";
  protected String            _rrdn        = "cn";
  protected String[]          _uoc         = {"inetOrgPerson","cougaarAcct"};
  protected String[]          _roc         = {"organizationalRole"};
  protected String            _rattr       = "roleOccupant";
  protected String            _passwordAttr= "userPassword";
  protected String            _authAttr    = "cougaarAuthReq";
  protected String            _enableAttr  = "cougaarAcctEnableTime";

  private static final int MAX_RETRIES = 3;
  private static final DateFormat DF=new SimpleDateFormat("yyyyMMddHHmmss'Z'");
  private static final TimeZone   GMT = TimeZone.getTimeZone("GMT");

  protected LdapUserServiceConfigurer _configurer;

  private static final String[] STRING_ARR = new String[1];
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

  private synchronized void checkContext() throws NamingException {
    if (_context == null) {
      Hashtable env = new Hashtable();
      setLdapEnvironment(env);
      _context = new InitialDirContext(env);
    }
  }

  private synchronized void resetContext() {
    _context = null;
    Hashtable env = new Hashtable();
    setLdapEnvironment(env);
    try {
      _context = new InitialDirContext(env);
    } catch (NamingException e) {
      System.out.println("LdapUserService: couldn't initialize connection to User LDAP database");
      e.printStackTrace();
    }
  }

  private void createUserBase() {
    BasicAttributes attrs = new BasicAttributes();
    attrs.put("objectClass","dcObject");
    int commaIndex = _userBase.indexOf(",");
    String dcComponent;
    if (commaIndex != -1) {
      dcComponent = _userBase.substring(0,commaIndex);
    } else {
      dcComponent = _userBase;
    }
    int equalIndex = dcComponent.indexOf("=");
    if (equalIndex == -1) {
      // real problem here!
      throw new IllegalStateException("Can't create user base -- the user base specified (" + _userBase + ") is not a dcObject");
    } 
    dcComponent = dcComponent.substring(equalIndex + 1);

    attrs.put("dc", dcComponent);
    try {
      _context.createSubcontext(_userBase, attrs);
    } catch (NamingException ne) {
      // ignore it... this is in the middle of another call, anyway
    }
  }

  private void createRoleBase() {
    BasicAttributes attrs = new BasicAttributes();
    attrs.put("objectClass","dcObject");
    int commaIndex = _roleBase.indexOf(",");
    String dcComponent;
    if (commaIndex != -1) {
      dcComponent = _roleBase.substring(0,commaIndex);
    } else {
      dcComponent = _roleBase;
    }
    int equalIndex = dcComponent.indexOf("=");
    if (equalIndex == -1) {
      // real problem here!
      throw new IllegalStateException("Can't create role base -- the role base specified (" + _roleBase + ") is not a dcObject");
    } 
    dcComponent = dcComponent.substring(equalIndex + 1);

    attrs.put("dc", dcComponent);
    try {
      _context.createSubcontext(_roleBase, attrs);
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
        return _context.search(_userBase,
                               "(&(" + field + "=" + text + "),(objectClass=" +
                               _uoc[0] + "))", 
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
        return _context.search(_userBase, "(&(" + filter + "),(objectClass=" +
                               _uoc[0] + "))",
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
    for (int i = 0; i < _uoc.length; i++) {
      oc.add(_uoc[i]);
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
      Attribute roleDN = attrs.get(_rrdn);
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
        return _context.search(_roleBase,
                               "(&(" + _rattr + "=" + uid2dn(uid) +
                               "),(objectClass=" + _roc[0] + "))",
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
        return _context.search(_roleBase,
                               "(&(" + field + "=" + searchText +
                               "),(objectClass=" + _roc[0] + "))", 
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
        return _context.search(_roleBase,
                               "(objectClass=" + _roc[0] + ")",
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
    attrs.put(_rattr, userDN);
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
    attrs.put(_rattr, uid2dn(uid));
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
    for (int i = 0; i < _roc.length; i++) {
      oc.add(_roc[i]);
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
    for (int i = 0; i < _roc.length; i++) {
      oc.add(_roc[i]);
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
    return _passwordAttr;
  }

  public String getUserRoleAttribute() {
    return _rattr;
  }

  public String getAuthFieldsAttribute() {
    return _authAttr;
  }

  public String getEnableTimeAttribute() {
    return _enableAttr;
  }

  public String getUserIDAttribute() {
    return _urdn;
  }

  public String getRoleIDAttribute() {
    return _rrdn;
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
        String values[] = null;
        String value = param[i].getValue().toString();
        if (param[i] instanceof KeyRuleParameter) {
          KeyRuleParameterEntry[] rules = 
            ((KeyRuleParameter) param[i]).getKeys();
          if (rules.length > 0) {
            values = new String[rules.length];
            for (int j = 0; j < rules.length; j++) {
              values[j] = rules[j].getValue();
            }
          }
        }
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
          if (values == null) {
            _uoc = new String[] {value};
          } else {
            _uoc = values;
          }
        } else if (PROP_ROC.equals(name)) {
          if (values == null) {
            _roc = new String[] {value};
          } else {
            _roc = values;
          }
        } else if (PROP_RATTR.equals(name)) {
          _rattr = value;
        } else if (PROP_PWDATTR.equals(name)) {
          _passwordAttr = value;
        } else if (PROP_AUTHATTR.equals(name)) {
          _authAttr = value;
        } else if (PROP_ETATTR.equals(name)) {
          _enableAttr = value;
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
          resetContext();
        }
      }
    }
  }
}
