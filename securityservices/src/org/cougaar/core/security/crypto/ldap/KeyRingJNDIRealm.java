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
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.security.cert.X509Certificate;
import java.security.Principal;

import org.apache.catalina.realm.JNDIRealm;
import org.apache.catalina.realm.GenericPrincipal;

/**
 * A Realm extension for Tomcat 4.0 that uses SSL to talk to
 * the JNDI ldap source for role and authentication information.
 * The KeyStore and TrustStore used are made available via the
 * KeyRingService and use the Node's certificates.                       <p>
 *
 * An example KeyRingJNDIRealm addition to server.xml which uses
 * anonymous binding to the ldap database:
 * <pre>
 *   &lt;Realm className="org.cougaar.security.crypto.ldap.KeyRingJNDIRealm" 
 *          connectionURL="ldaps://chump"
 *          roleBase="dc=roles,dc=nai,dc=com"
 *          roleName="cn"
 *          roleSearch="(uniqueMember={0})"
 *          roleSubtree="false"
 *          userPassword="userPassword"
 *          userPattern="cn={0},dc=nai,dc=com"
 *          debug="-1" />
 * </pre>
 * <code>KeyRingJNDIRealm</code> supports all of Tomcat's JNDIRealm
 * configuration parameters, but modifies the meaning of the
 * <code>connectionURL</code>. URL's beginning with "ldaps://" 
 * will use SSL to communicate with the server and have a default
 * port number of 636 instead of 389.<p>
 *
 * Additionally, if a client certificate is used for gathering role
 * information the subject's distinguished name will replace the user
 * distinguished name in the roleSearch. In case only a single
 * portion of the subject's dn is to be used, set the 
 * <code>certAuth</code> attribute to the component that is to be
 * used (e.g. "CN").
 *
 * @see org.apache.catalina.realm.JNDIRealm
 * @see SecureJNDIRealm
 * @author George Mount <gmount@nai.com>
 */
public class KeyRingJNDIRealm extends JNDIRealm {

  String _certAuth;

  /** Default constructor */
  public KeyRingJNDIRealm() {}

  /**
   * Open (if necessary) and return a connection to the configured
   * directory server for this Realm.
   *
   * @exception NamingException if a directory server error occurs
   */
  protected DirContext open() throws NamingException {
    if (context == null) {

      if (debug >= 1)
        log("Connecting to URL " + connectionURL);

      Hashtable env = new Hashtable(11);

      env.put(Context.INITIAL_CONTEXT_FACTORY, contextFactory);
      if (connectionName != null)
        env.put(Context.SECURITY_PRINCIPAL, connectionName);
      if (connectionPassword != null)
        env.put(Context.SECURITY_CREDENTIALS, connectionPassword);

      boolean useSSL = false;
      String url = connectionURL;
      if (url != null && url.startsWith("ldaps://")) {
        useSSL = true;
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
      }

      if (url != null)
        env.put(Context.PROVIDER_URL, url);

      if (useSSL) {
        env.put(Context.SECURITY_PROTOCOL, "ssl");
        
        env.put("java.naming.ldap.factory.socket", 
                "org.cougaar.core.security.crypto.ldap.KeyRingSSLFactory");
      }
      context = new InitialDirContext(env);
    }
    return context;
  }

  /**
   * Returns the certificate subject's domain component to be used in
   * case the subject is not to be used. Returns <code>null</code> if
   * the full dn is to be used.
   */
  public String getCertAuth() {
    return _certAuth;
  }

  /**
   * Set the certificate subject's domain component to be used in
   * case the subject is not to be used. certAuth can be
   * <code>null</code> or empty string to use the full subject dn.
   */
  public void setCertAuth(String certAuth) {
    if (certAuth != null && certAuth.length() == 0) {
      certAuth = null;
    }
    _certAuth = certAuth;
  }

  public Principal authenticate(String username, String credentials) {
    System.err.println("authenticate(String username, String credentials)");
    return super.authenticate(username,credentials);
  }
  public Principal authenticate(String username, byte[] credentials) {
    System.err.println("authenticate(String username, byte[] credentials)");
    return super.authenticate(username,credentials);
  }
    public Principal authenticate(String username, String clientDigest,
                                  String nOnce, String nc, String cnonce,
                                  String qop, String realm,
                                  String md5a2) {
      System.err.println("    public Principal authenticate(String username, String clientDigest,...");
      return super.authenticate(username,clientDigest,nOnce,nc,cnonce,qop,realm,md5a2);
    }
  /**
   * Return the Principal associated with the specified chain of X509
   * client certificates.  If there is none, return <code>null</code>.
   *
   * @param certs Array of client certificates, with the first one in
   *  the array being the certificate of the client itself.
   */
  public Principal authenticate(X509Certificate certs[]) {

    System.err.println("Trying to authenticate the certificates");
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

    String dn,un,subjectDN;
    boolean noRoles = false;

    subjectDN = certs[0].getSubjectDN().getName();
    un = getUserName(subjectDN);
    if (un == null) {
      System.err.println("un = null");
      return null;
    }

    dn = getUserDN(subjectDN,un);
    if (dn == null) {
      System.err.println("dn = null");
      return null;
    }

    List       roles   = getRoles(un,dn);
    System.err.println("Got roles for " + un);
    return new GenericPrincipal(this, un, null, roles);
  }

  /**
   * If certAuth is set, the certAuth component
   * of the subject DN is returned. Otherwise
   * the entire subjectDN is returned.
   */
  protected String getUserName(String subjectDN) {
    if ( _certAuth == null) return subjectDN;

    int start = subjectDN.indexOf(_certAuth + "=");
    if (start == -1) {
      // doesn't contain the required component!
      return null;
    }
    start += _certAuth.length() + 1;
    int end = subjectDN.indexOf(",",start);
    if (end == -1) {
      return subjectDN.substring(start);
    } 
    return subjectDN.substring(start,end);
  }

  /**
   * returns the subjectDN if the certAuth is not set or 
   * fabricates a DN from the userName if certAuth is set
   */
  protected String getUserDN(String subjectDN, String userName) {
    if ( _certAuth == null) return subjectDN;
    return userFormat.format(new String[] { userName });
  }

  /**
   * Returns the roles for the given user name (un) and
   * user's distinguished name (dn).
   */
  protected List getRoles(String un, String dn) {
    List       roles   = null;
    DirContext context = null;;
    try {
      // Ensure that we have a directory context available
      context = open();
      roles = getRoles(context,un,dn);
      release(context);
    } catch (NamingException e) {

      // Log the problem for posterity
      super.log(sm.getString("jndiRealm.exception"), e);

      // Close the connection so that it gets reopened next time
      if (context != null) {
        close(context);
      }
      // authenticated, but no roles
    }
    return roles;
  }
}
