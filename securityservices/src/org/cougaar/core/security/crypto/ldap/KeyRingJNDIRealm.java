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
import java.util.Calendar;
import java.util.TimeZone;
import java.util.StringTokenizer;
import java.text.SimpleDateFormat;
import java.text.DateFormat;

import java.security.Principal;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.NoSuchAlgorithmException;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.Attributes;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchResult;

import org.apache.catalina.Container;
import org.apache.catalina.realm.RealmBase;
import org.apache.catalina.core.ContainerBase;
import org.cougaar.core.security.acl.auth.DualAuthenticator;

import org.cougaar.core.security.services.crypto.LdapUserService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.security.services.identity.AgentIdentityService;
import org.cougaar.core.security.services.identity.PendingRequestException;
import org.cougaar.core.security.services.identity.IdentityDeniedException;


/**
 * A Realm extension for Tomcat 4.0 that uses SSL to talk to
 * the JNDI ldap source for role and authentication information.
 * The KeyStore and TrustStore used are made available via the
 * KeyRingService and use the Node's certificates.                       <p>
 *
 * An example KeyRingJNDIRealm addition to server.xml:
 * <pre>
 *   &lt;Realm className="org.cougaar.security.crypto.ldap.KeyRingJNDIRealm" 
 *          certComponent="CN"
 *          debug="-1" />
 * </pre>
 * <code>KeyRingJNDIRealm</code> uses the <code>LdapUserService</code>
 * for access to the LDAP database. In order to convert certificate
 * subject DN's to LDAP DN's, the component used to distinguish the
 * user must be pulled from the Certificate. The component to use should be
 * specified in the certComponent attribute. The default is "CN".
 *
 * @see org.apache.catalina.realm.JNDIRealm
 * @see SecureJNDIRealm
 * @author George Mount <gmount@nai.com>
 */
public class KeyRingJNDIRealm extends RealmBase {
  private static ServiceBroker    _nodeServiceBroker;
  private static final DateFormat LDAP_TIME =
    new SimpleDateFormat("yyyyMMddHHmmss'Z'");
  private static final TimeZone   GMT = TimeZone.getTimeZone("GMT");
  private LdapUserService _userService;
  private String          _certComponent = "CN";
  private static String   _realmName = "Cougaar";

  /** 
   * Default constructor. Uses <code>LdapUserService</code>
   * given in the setDefaultLdapUserService call.
   */
  public KeyRingJNDIRealm() {
    _userService = (LdapUserService) _nodeServiceBroker.
      getService(this, LdapUserService.class, null);
    if (_nodeServiceBroker != null) {
      AgentIdentityService ais = (AgentIdentityService)
        _nodeServiceBroker.getService(this, AgentIdentityService.class, null);
      if (ais != null) {
        // force a certificate for the node
        try {
          ais.CreateCryptographicIdentity(NodeInfo.getNodeName(), null);
        } catch (PendingRequestException e) {
          // well, can't use it, but no biggy
        } catch (IdentityDeniedException e) {
          e.printStackTrace();
        }
      }
    }
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
   * Returns the certificate subject's component to be used in
   * case the subject is not to be used. Returns <code>null</code> if
   * the full dn is to be used.
   */
  public String getCertComponent() {
    return _certComponent;
  }
 
  /**
   * Set the certificate subject's domain component to be used in
   * case the subject is not to be used. 
   *
   * certComponent cannot be
   * <code>null</code> or empty string.
   *
   * @param certComponent The attribute from the certificate
   *                      subject DN to use as the user id.
   */
  public void setCertComponent(String certComponent) {
    if (certComponent != null && certComponent.length() == 0) {
      throw new IllegalArgumentException("certComponent may not be null or empty string");
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
   * @return A <code>CougaarPrincipal</code> representing the user
   * if the credentials match the database or <code>null</code> otherwise.
   */
  public Principal authenticate(String username, String credentials) {
//     System.out.println("Authenticating " + username + " with " + credentials);
    if (username == null || credentials == null) {
      return null;
    }
    try {
      Attributes attrs = _userService.getUser(username);
      if (!passwordOk(username, credentials, attrs)) {
        return null;
      }
      return getPrincipal(attrs);
    } catch (NamingException e) {
      return null;
    }
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

    user = getUserName(user);
    if (user == null) {
      // certificate is bad, bad, bad!
      return null;
    }

    try {
//       System.out.println("Getting attributes for user: " + user);
      Attributes attrs = _userService.getUser(user);
      if (attrs == null) {
        return null; // user isn't in the database
      }
      if (!userDisabled(attrs)) {
        return getPrincipal(attrs);
      }
    } catch (NamingException ne) {
      ne.printStackTrace();
    }
    return null;
  }

  /**
     * Return the Principal associated with the specified username, which
     * matches the digest calculated using the given parameters using the
     * method described in RFC 2069; otherwise return <code>null</code>.
     *
     * @param username Username of the Principal to look up
     * @param clientDigest Digest which has been submitted by the client
     * @param nOnce Unique (or supposedly unique) token which has been used
     * for this request
     * @param realm Realm name
     * @param md5a2 Second MD5 digest used to calculate the digest :
     * MD5(Method + ":" + uri)
   */
  public Principal authenticate(String username, String clientDigest,
                                String nOnce, String nc, String cnonce,
                                String qop, String realm,
                                String md5a2) {
    /*
      System.out.println("Digest : " + clientDigest);
      
      System.out.println("************ Digest info");
      System.out.println("Username:" + username);
      System.out.println("ClientSigest:" + clientDigest);
      System.out.println("nOnce:" + nOnce);
      System.out.println("nc:" + nc);
      System.out.println("cnonce:" + cnonce);
      System.out.println("qop:" + qop);
      System.out.println("realm:" + realm);
      System.out.println("md5a2:" + md5a2);
    */
    try {
      Attributes userAttrs = _userService.getUser(username);
      Attribute pwdAttr = userAttrs.get(_userService.getPasswordAttribute());
      if (pwdAttr == null || pwdAttr.size() == 0) {
//         System.out.println("Password attribute: " + pwdAttr);
        return null;
      }
      String md5a1;
      Object pwdVal = pwdAttr.get();
      if (pwdVal instanceof byte[]) {
        md5a1 = new String((byte[]) pwdVal);
      } else {
        md5a1 = pwdVal.toString();
      }
//       System.out.println("md5a1 = " + md5a1);
      if (md5a1 == null)
        return null;
      String serverDigestValue = md5a1 + ":" + nOnce + ":" + nc + ":"
        + cnonce + ":" + qop + ":" + md5a2;
      String serverDigest = this.md5Encoder.
        encode(md5Helper.digest(serverDigestValue.getBytes()));
//       System.out.println("Server digest : " + serverDigest);
      
      if (serverDigest.equals(clientDigest))
        return getPrincipal(userAttrs);
    } catch (NamingException ne) {
      ne.printStackTrace();
    }
    return null;
  }

  /**
   * Returns a message digest associated with the given principal's
   * user name and password.
   */
  public static String encryptPassword(String username, String pwd) {
    String digestValue = username + ":" + _realmName + ":" + pwd;
//     System.out.println("Getting password digest for " + digestValue);
    byte[] digest =
      md5Helper.digest(digestValue.getBytes());
    return md5Encoder.encode(digest);
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
   * Returns <code>null</code> always. 
   *
   * This is not used.
   */
  protected Principal getPrincipal(String username) {
    return null;
  }

  /**
   * Creates a principal with associated roles based off of the
   * LDAP user attributes.
   *
   * @param userAttr The user attributes returned from the database
   * @return A <code>CougaarPrincipal</code> associated with the
   * user, having the roles assigned to that user.
   */
  protected Principal getPrincipal(Attributes userAttr) {
    try {
      String username = userAttr.get(_userService.getUserIDAttribute()).
        get().toString();
      Attribute authAttr = userAttr.get(_userService.getAuthFieldsAttribute());
      String authFields = "EITHER";
      if (authAttr != null) {
        Object val = authAttr.get();
        if (val != null) {
          authFields = val.toString();
        }
      }
      NamingEnumeration ne = _userService.getRoles(username);
//       System.out.println("Got roles for " + username);
      ArrayList roles = new ArrayList();
      while (ne.hasMore()) {
        SearchResult result = (SearchResult) ne.next();
        Attributes attrs = result.getAttributes();
        String role = attrs.get(_userService.getRoleIDAttribute()).get().toString();
        roles.add(role);
//         System.out.println("  role: " + role);
      }
      return new CougaarPrincipal(this, username, roles, authFields);
    } catch (NamingException e) {
//       System.out.println("Caught exception: ");
      e.printStackTrace();
      return null;
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
  protected boolean passwordOk(String username,  String password, 
                               Attributes attrs)
    throws NamingException {
    boolean match = false;
    if (attrs == null) return false;

    if (userDisabled(attrs)) {
//       System.out.println("Password login isn't ok.");
      return false;
    }
    Attribute  attr  = attrs.get(_userService.getPasswordAttribute());
//     System.out.println("attr = " + attr);
    if (attr == null || attr.size() < 1) return false;

    Object     attrVal = attr.get();
//     System.out.println("attrVal = " + attrVal);
    if (attrVal == null) return false;

    String passwordCheck;
    if (attrVal instanceof byte[]) {
      passwordCheck = new String((byte[]) attrVal);
    } else {
      passwordCheck = attrVal.toString();
    }

    password = encryptPassword(username, password);
    if (hasMessageDigest()) {
      match = digest(password).equalsIgnoreCase(passwordCheck);
    } else {
      match = digest(password).equals(passwordCheck);
    }

    // in the future log a password match failure in a finally block
    return match;
  }

  /**
   * Returns true if the user account has been disabled
   */
  private boolean userDisabled(Attributes attrs) throws NamingException {
    Attribute attr = attrs.get(_userService.getEnableTimeAttribute());
    if (attr != null) {
      Object attrVal = attr.get();
      if (attrVal != null) {
        String val = attrVal.toString();
        Calendar now = Calendar.getInstance(GMT);
        String nowStr = LDAP_TIME.format(now.getTime());
        if (nowStr.compareToIgnoreCase(val) >= 0) {
          return false;
        }
      }
    }
    return true;
  }

  /**
   * Converts a certificate subject DN to an LDAP DN.
   */
  static String certSubjectToLdapDN(String certDN) {
    StringBuffer dn = new StringBuffer();
    StringTokenizer tok = new StringTokenizer(certDN,"/");
    boolean first = true;
    
    while (tok.hasMoreTokens()) {
      if (first) {
        first = false;
      } else {
        dn.append(',');
      }
      dn.append(tok.nextToken());
    }
    return dn.toString();
  }

  /**
   * Return a short name for this Realm implementation, 
   * for use in log messages.
   */
  public String getName() {
    return "KeyRing JNDI Realm";
  }

  /**
   * Set the Container with which this Realm has been associated.
   *
   * @param container The associated Container
   */
  public void setContainer(Container container) {
    super.setContainer(container);
    DualAuthenticator daValve = findDAValve(container);
    if (daValve != null) {
      _realmName = daValve.getRealmName();
    }
  }

  private DualAuthenticator findDAValve(Container container) {
    Container[] children = container.findChildren();
    for (int i = 0; i < children.length; i++) {
      if (children[i] instanceof DualAuthenticator) {
        return (DualAuthenticator) children[i];
      }
      DualAuthenticator da = findDAValve(children[i]);
      if (da != null) {
        return da;
      }
    }
    return null;
  }

  static {
    if (md5Helper == null) {
      try {
        md5Helper = MessageDigest.getInstance("MD5");
      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
      }
    }
  }
}
