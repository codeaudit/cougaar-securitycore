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
import java.util.List;
import java.util.ArrayList;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.security.cert.X509Certificate;
import java.security.Principal;
import javax.naming.directory.Attributes;
import javax.naming.directory.Attribute;
import javax.naming.NamingException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;

import org.apache.catalina.realm.RealmBase;
import org.apache.catalina.realm.GenericPrincipal;
import org.cougaar.core.security.services.crypto.LdapUserService;
import org.cougaar.core.component.ServiceBroker;

/**
 * A Realm extension for Tomcat 4.0 that uses SSL to talk to
 * the JNDI ldap source for role and authentication information.
 * The KeyStore and TrustStore used are made available via the
 * KeyRingService and use the Node's certificates.                       <p>
 *
 * An example KeyRingJNDIRealm addition to server.xml:
 * <pre>
 *   &lt;Realm className="org.cougaar.security.crypto.ldap.KeyRingJNDIRealm" 
 *          roleName="cn"
 *          userPassword="userPassword"
 *          certComponent="CN"
 *          debug="-1" />
 * </pre>
 * <code>KeyRingJNDIRealm</code> uses the <code>LdapUserService</code>
 * for access to the LDAP database so only the roleName and userPassword
 * attributes need to be set.
 *
 * Additionally, if a client certificate is used for gathering role
 * information the subject's distinguished name will replace the user
 * distinguished name in the roleSearch. In case only a single
 * portion of the subject's dn is to be used, set the 
 * <code>certComponent</code> attribute to the component that is to be
 * used (e.g. "CN").
 *
 * @see org.apache.catalina.realm.JNDIRealm
 * @see SecureJNDIRealm
 * @author George Mount <gmount@nai.com>
 */
public class KeyRingJNDIRealm extends RealmBase {
  private static ServiceBroker _nodeServiceBroker;
  private LdapUserService _userService;
  private String          _certComponent;
  private String          _passwordAttr;
  private String          _roleAttr;

  /** 
   * Default constructor. Uses <code>LdapUserService</code>
   * given in the setDefaultLdapUserService call.
   */
  public KeyRingJNDIRealm() {
    _userService = (LdapUserService) _nodeServiceBroker.
      getService(this, LdapUserService.class, null);
  }

  /** 
   * Constructor that uses the given LdapUserService for
   * its connection to the User LDAP database.
   */
  public KeyRingJNDIRealm(LdapUserService ldap) {
    _userService = ldap;
  }

  /**
   * Sets the default LdapUserService using the node service broker
   */
  public static void setNodeServiceBroker(ServiceBroker sb) {
    _nodeServiceBroker = sb;
  }

  /**
   * Returns the attribute to use for password comparison. The
   * default is "userPassword"
   */
  public String getUserPassword() {
    return _passwordAttr;
  }

  /**
   * Sets the attribute to use for password comparison.
   */
  public void setUserPassword(String passwordAttribute) {
    _passwordAttr = passwordAttribute;
  }

  /**
   * Returns the attribute to use as the role name. The
   * default is "cn"
   */
  public String getRoleName() {
    return _roleAttr;
  }

  /**
   * Sets the attribute to use for the role name
   */
  public void setRoleName(String roleAttribute) {
    _roleAttr = roleAttribute;
  }

  /**
   * Returns the certificate subject's component to be used in
   * case the subject is not to be used. Returns <code>null</code> if
   * the full dn is to be used.
   */
  public String getCertComponent() {
    return _certComponent;
  }
 
  /**
   * Set the certificate subject's domain component to be used in
   * case the subject is not to be used. certComponent can be
   * <code>null</code> or empty string to use the full subject dn.
   */
  public void setCertComponent(String certComponent) {
    if (certComponent != null && certComponent.length() == 0) {
      certComponent = null;
    }
    _certComponent = certComponent;
  }

  /**
   * Authenticate the user with the given credentials against the
   * LDAP database.
   *
   * @param username The user id of the user
   * @param credentials The given authentication credentials (password)
   *                    to check against the password
   * @return A <code>GenericPrincipal</code> representing the user
   * if the credentials match the database or <code>null</code> otherwise.
   */
  public Principal authenticate(String username, String credentials) {
    if (!passwordOk(username, credentials)) {
      return null;
    }
    return getPrincipal(username);
  }

  /**
   * Return the Principal associated with the specified chain of X509
   * client certificates.  If there is none, return <code>null</code>.
   *
   * @param certs Array of client certificates, with the first one in
   *  the array being the certificate of the client itself.
   */
  public Principal authenticate(X509Certificate certs[]) {

//     System.out.println("Trying to authenticate the certificates");
    if ( (certs == null) || (certs.length < 1) )
      return null;

    // Check the validity of each certificate in the chain
    for (int i = 0; i < certs.length; i++) {
      try {
        certs[i].checkValidity();
      } catch (Exception e) {
        if (debug >= 2) super.log("  Validity exception", e);
        System.err.println("Error with validity: " + e);
        return null;
      }
    }

    String user = certs[0].getSubjectDN().getName();

    if (_certComponent != null) {
      user = getUserName(user);
      if (user == null) {
        // certificate is bad, bad, bad!
        return null;
      }
    }
      
    return getPrincipal(user);
  }

  /**
   * If certComponent is set, the certComponent component
   * of the subject DN is returned. Otherwise
   * the entire subjectDN is returned.
   */
  protected String getUserName(String subjectDN) {
    int start = subjectDN.indexOf(_certComponent + "=");
    if (start == -1) {
      // doesn't contain the required component!
      return null;
    }
    start += _certComponent.length() + 1;
    int end = subjectDN.indexOf(",",start);
    if (end == -1) {
      return subjectDN.substring(start);
    } 
    return subjectDN.substring(start,end);
  }

  /**
   * Creates a principal with associated roles based off of the
   * user name given
   *
   * @param username The user to establish as the Principal
   * @returns A <code>GenericPrincipal</code> associated with the
   * user, having the roles assigned to that user.
   */
  protected Principal getPrincipal(String username) {
//     System.out.println("getting principal for: " + username);
    try {
      NamingEnumeration ne = _userService.getRoles(username);
//       System.out.println("Got roles for " + username);
      ArrayList roles = new ArrayList();
      while (ne.hasMore()) {
        SearchResult result = (SearchResult) ne.next();
        Attributes attrs = result.getAttributes();
        String role = attrs.get(_roleAttr).get().toString();
        roles.add(role);
//         System.out.println("  role: " + role);
      }
      return new GenericPrincipal(this, username, null, roles);
    } catch (NamingException e) {
//       System.out.println("Caught exception: ");
//       e.printStackTrace();
      return new GenericPrincipal(this, username, null);
    }
  }

  /**
   * Supposed to return the password for comparison by base class,
   * but we do not ever have the password. Therefore, we override
   * all the authentication functions and just return null here.
   */
  public String getPassword(String username) {
    return null;
  }

  /**
   * Returns true if the given user/password match the database.
   * Also logs failures to M&R.
   */
  protected boolean passwordOk(String user, String password) {
    boolean match = false;
    try {
      Attributes attrs = _userService.getUser(user);
      if (attrs == null) return false;

      Attribute  attr  = attrs.get(_passwordAttr);
      if (attr == null) return false;

      Object     attrVal = attr.get();
      if (attrVal == null) return false;

      String passwordCheck;
      if (attrVal instanceof byte[]) {
        passwordCheck = new String((byte[]) attrVal);
      } else {
        passwordCheck = attrVal.toString();
      }

      if (hasMessageDigest()) {
        match = digest(password).equalsIgnoreCase(passwordCheck);
      } else {
        match = digest(password).equals(passwordCheck);
      }

      // in the future log a password match failure in a finally block
      return match;
    } catch (NamingException e) {
      return false;
    }
  }

  /**
   * Return a short name for this Realm implementation, 
   * for use in log messages.
   */
  public String getName() {
    return "KeyRing JNDI Realm";
  }
}
