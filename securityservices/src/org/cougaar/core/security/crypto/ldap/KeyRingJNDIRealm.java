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

import java.util.Iterator;
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
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.Attributes;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchResult;

import org.apache.catalina.Container;
import org.apache.catalina.Valve;
import org.apache.catalina.realm.RealmBase;
import org.apache.catalina.core.ContainerBase;

// IDMEF
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.DetectTime;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.IDMEF_Process;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.User;
import edu.jhuapl.idmef.UserId;
import edu.jhuapl.idmef.AdditionalData;

// Cougaar security infrastructure
import org.cougaar.core.security.acl.auth.DualAuthenticator;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;

// Cougaar core infrastructure
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.identity.*;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.node.NodeIdentifier;
import org.cougaar.core.security.services.crypto.LdapUserService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.service.LoggingService;

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
 *          debug="-1" /&gt;
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
public class KeyRingJNDIRealm extends RealmBase implements BlackboardClient {

  private static ServiceBroker _nodeServiceBroker;
  private static String        _realmName = "Cougaar";
  private LoggingService log;

  private static final DateFormat LDAP_TIME =
    new SimpleDateFormat("yyyyMMddHHmmss'Z'");
  private static final TimeZone   GMT = TimeZone.getTimeZone("GMT");

  private String                     _certComponent = "CN";
  private LdapUserService            _userService;

  private static BlackboardService   _blackboardService;
  private static IdmefMessageFactory _idmefFactory;
  private static CmrFactory          _cmrFactory;
  private static SensorInfo          _sensor;

  public static final int    LF_USER_DOESNT_EXIST       = 0;
  public static final int    LF_LDAP_ERROR              = 1;
  public static final int    LF_CERTIFICATE_INVALID     = 2;
  public static final int    LF_BAD_CERTIFICATE_SUBJECT = 3;
  public static final int    LF_USER_DISABLED           = 4;
  public static final int    LF_LDAP_PASSWORD_NULL      = 5;
  public static final int    LF_PASSWORD_MISMATCH       = 6;
  public static final int    LF_USER_MISMATCH           = 7;
  public static final int    LF_REQUIRES_CERT           = 8;

  public static final String LOGIN_FAILURE_ID = "LOGINFAILURE";
  public static final String FAILURE_REASON = "Reason for login failure";
  public static final Classification LOGINFAILURE = 
    new Classification(LOGIN_FAILURE_ID, "", Classification.VENDOR_SPECIFIC);

  protected static final AdditionalData REASONS[][] = {
    {new AdditionalData(AdditionalData.STRING, FAILURE_REASON,
                        "user does not exist")},
    {new AdditionalData(AdditionalData.STRING, FAILURE_REASON,
                        "database error")},
    {new AdditionalData(AdditionalData.STRING, FAILURE_REASON,
                        "user certificate is invalid")},
    {new AdditionalData(AdditionalData.STRING, FAILURE_REASON,
                        "invalid subject in user certificate")},
    {new AdditionalData(AdditionalData.STRING, FAILURE_REASON,
                        "the user account has been disabled")},
    {new AdditionalData(AdditionalData.STRING, FAILURE_REASON,
                        "the password for the user is null in the database")},
    {new AdditionalData(AdditionalData.STRING, FAILURE_REASON,
                        "the user has entered the wrong password")},
    {new AdditionalData(AdditionalData.STRING, FAILURE_REASON,
                        "dual authentication user names are different")},
    {new AdditionalData(AdditionalData.STRING, FAILURE_REASON,
                        "requires user certificate")}
  };

  /** 
   * Default constructor. Uses <code>LdapUserService</code>
   * given in the setDefaultLdapUserService call.
   */
  public KeyRingJNDIRealm() {
    init();
  }

  private synchronized boolean init() {
    if (_nodeServiceBroker == null) {
      return false;
    }
    log = (LoggingService)
      _nodeServiceBroker.getService(this,
			       LoggingService.class, null);
    if (_userService == null) {
      _userService = (LdapUserService) _nodeServiceBroker.
        getService(this, LdapUserService.class, null);
    }
    return true;
  }

  /**
   * Sets the default LdapUserService using the node service broker
   */
  public static void setNodeServiceBroker(ServiceBroker sb) {
    _nodeServiceBroker = sb;
  }

  /**
   * Sets the message factory and BlackboardService to use
   */
  public static synchronized void initAlert(IdmefMessageFactory mf,
                                            CmrFactory cf,
                                            BlackboardService bbs,
                                            SensorInfo sensor) {
    _idmefFactory = mf;
    _cmrFactory = cf;
    _blackboardService = bbs;
    _sensor = sensor;
  }

  /**
   * Returns true if the IDMEF message service is initialized
   */
  public static boolean isAlertInitialized() {
    return (_idmefFactory != null);
  }

  /**
   * Sets the realm name for use in DIGEST
   * and BASIC authentication.
   */
  public static void setRealmName(String realmName) {
    _realmName = realmName;
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
//     log.debug("Authenticating " + username + " with " + credentials);
    if (!init() || username == null || credentials == null) {
      // don't alert that there was no credentials -- that happens
      // under normal opera1tion
      return null;
    }
    try {
      Attributes attrs = _userService.getUser(username);
      if (!passwordOk(username, credentials, attrs)) {
        return null;
      }
      return getPrincipal(attrs);
    } catch (NameNotFoundException e) {
      alertLoginFailure(LF_USER_DOESNT_EXIST, username);
    } catch (NamingException e) {
      alertLoginFailure(LF_LDAP_ERROR, username);
      e.printStackTrace();
    }
    return null;
  }

  /**
   * Return the Principal associated with the specified chain of X509
   * client certificates.  If there is none, return <code>null</code>.
   *
   * @param certs Array of client certificates, with the first one in
   *  the array being the certificate of the client itself.
   */
  public Principal authenticate(X509Certificate certs[]) {

//     log.debug("Trying to authenticate the certificates");
    if ( !init() || certs == null || certs.length < 1 ) {
      // don't log this -- there aren't any certificates and that's ok
      return null;
    }

    // Check the validity of each certificate in the chain
    for (int i = 0; i < certs.length; i++) {
      try {
        certs[i].checkValidity();
      } catch (Exception e) {
        alertLoginFailure(LF_CERTIFICATE_INVALID, null);
        if (debug >= 2) super.log("  Validity exception", e);
        System.err.println("Error with validity: " + e);
        return null;
      }
    }

    String userdn = certs[0].getSubjectDN().getName();

    String user = getUserName(userdn);
    if (user == null) {
      // certificate is bad, bad, bad!
      alertLoginFailure(LF_BAD_CERTIFICATE_SUBJECT, userdn);
      return null;
    }

    try {
//       log.debug("Getting attributes for user: " + user);
      Attributes attrs = _userService.getUser(user);
      if (attrs == null) {
        alertLoginFailure(LF_USER_DOESNT_EXIST, user);
        return null; // user isn't in the database
      }
      if (!userDisabled(attrs)) {
        return getPrincipal(attrs);
      } else {
        alertLoginFailure(LF_USER_DISABLED, user);
      }
    } catch (NameNotFoundException nnfe) {
      alertLoginFailure(LF_USER_DOESNT_EXIST, user);
      nnfe.printStackTrace();
    } catch (NamingException ne) {
      alertLoginFailure(LF_LDAP_ERROR, user);
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
      log.debug("Digest : " + clientDigest);
      
      log.debug("************ Digest info");
      log.debug("Username:" + username);
      log.debug("ClientSigest:" + clientDigest);
      log.debug("nOnce:" + nOnce);
      log.debug("nc:" + nc);
      log.debug("cnonce:" + cnonce);
      log.debug("qop:" + qop);
      log.debug("realm:" + realm);
      log.debug("md5a2:" + md5a2);
    */
    if (!init()) return null;
    try {
      Attributes userAttrs = _userService.getUser(username);
      Attribute pwdAttr = userAttrs.get(_userService.getPasswordAttribute());
      if (pwdAttr == null || pwdAttr.size() == 0) {
        alertLoginFailure(LF_LDAP_PASSWORD_NULL, username);
//         log.debug("Password attribute: " + pwdAttr);
        return null;
      }
      String md5a1;
      Object pwdVal = pwdAttr.get();
      if (pwdVal instanceof byte[]) {
        md5a1 = new String((byte[]) pwdVal);
      } else {
        md5a1 = pwdVal.toString();
      }

//       log.debug("md5a1 = " + md5a1);
      String serverDigestValue = md5a1 + ":" + nOnce + ":" + nc + ":"
        + cnonce + ":" + qop + ":" + md5a2;
      String serverDigest = this.md5Encoder.
        encode(md5Helper.digest(serverDigestValue.getBytes()));
//       log.debug("Server digest : " + serverDigest);
      
      if (serverDigest.equals(clientDigest))
        return getPrincipal(userAttrs);
      
      alertLoginFailure(LF_PASSWORD_MISMATCH, username);
    } catch (NameNotFoundException nnfe) {
      alertLoginFailure(LF_USER_DOESNT_EXIST, username);
      nnfe.printStackTrace();
    } catch (NamingException ne) {
      alertLoginFailure(LF_LDAP_ERROR, username);
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
//     log.debug("Getting password digest for " + digestValue);
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
    String username = null;
    String authFields = "EITHER";
    if (_userService == null) return null;
    try {
      username = userAttr.get(_userService.getUserIDAttribute()).
        get().toString();
      Attribute authAttr = userAttr.get(_userService.getAuthFieldsAttribute());
      if (authAttr != null) {
        Object val = authAttr.get();
        if (val != null) {
          authFields = val.toString();
        }
      }
      NamingEnumeration ne = _userService.getRoles(username);
//       log.debug("Got roles for " + username);
      ArrayList roles = new ArrayList();
      while (ne.hasMore()) {
        SearchResult result = (SearchResult) ne.next();
        Attributes attrs = result.getAttributes();
        String role = attrs.get(_userService.getRoleIDAttribute()).get().toString();
        roles.add(role);
//         log.debug("  role: " + role);
      }
      return new CougaarPrincipal(this, username, roles, authFields);
    } catch (NamingException e) {
      if (username != null) {
        return new CougaarPrincipal(this, username, null, authFields);
      }
      alertLoginFailure(LF_LDAP_ERROR, username);
//       log.debug("Caught exception: ");
      e.printStackTrace();
    }
    return null;
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
    if (attrs == null) {
      alertLoginFailure(LF_USER_DOESNT_EXIST, username);
      return false;
    }

    if (userDisabled(attrs)) {
//       log.debug("Password login isn't ok.");
      alertLoginFailure(LF_USER_DISABLED, username);
      return false;
    }
    Attribute  attr  = attrs.get(_userService.getPasswordAttribute());
//     log.debug("attr = " + attr);
    if (attr == null || attr.size() < 1) {
      alertLoginFailure(LF_LDAP_PASSWORD_NULL, username);
      return false;
    }

    Object     attrVal = attr.get();
//     log.debug("attrVal = " + attrVal);
    if (attrVal == null) {
      alertLoginFailure(LF_LDAP_PASSWORD_NULL, username);
      return false;
    }

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

    if (!match) {
      alertLoginFailure(LF_PASSWORD_MISMATCH, username);
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

  private synchronized boolean initAlert(ServiceBroker sb) {
    if (sb == null) return false;
    try {
    if (_idmefFactory == null) {
      _blackboardService =
        (BlackboardService) sb.getService(this, BlackboardService.class, null);
      DomainService ds = 
        (DomainService) sb.getService(this, DomainService.class, null);
      if (ds == null) {
        log.error("Error: There is no DomainService. I cannot alert on login failures.");
        log.error("Service Broker's services:");
        Iterator iter = sb.getCurrentServiceClasses();
        while (iter.hasNext()) {
          Object o = iter.next();
          log.error("   " + o);
        }
        log.error("-------------------------------------------");
      } else {
        _cmrFactory = (CmrFactory) ds.getFactory("cmr");
        _idmefFactory = _cmrFactory.getIdmefMessageFactory();
      
        List capabilities = new ArrayList();
        capabilities.add(LOGINFAILURE);
      
        RegistrationAlert reg = 
          _idmefFactory.createRegistrationAlert( _sensor, capabilities,
                                                 _idmefFactory.newregistration ,_idmefFactory.SensorType);
        NewEvent regEvent = _cmrFactory.newEvent(reg);
      
        boolean close = true;
        try {
          close = _blackboardService.tryOpenTransaction();
        } catch (Exception e) {
          close = false;
          e.printStackTrace();
        }
        _blackboardService.publishAdd(regEvent);
        try {
          if (close) _blackboardService.closeTransaction();
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
    }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return (_idmefFactory != null);
  }

  public void alertLoginFailure(int failureType, String userName) {
    alertLoginFailure(failureType, userName, null);
  }

  public void alertLoginFailure(int failureType, String userName1, 
                                String userName2) {
    if (!isAlertInitialized()) {
      log.debug("Couldn't alert about " + 
                         REASONS[failureType][0].getAdditionalData() +
                         ", userName1: " + userName1 + ", userName2: " +
                         userName2);
      return; // can't alert without IDMEF factory
    }
    ArrayList cfs = new ArrayList();
    cfs.add(LOGINFAILURE);
    DetectTime dt = new DetectTime();
    Alert alert = _idmefFactory.createAlert(_sensor, new DetectTime(),
                                            null, null, cfs, null);

    
    alert.setAdditionalData(REASONS[failureType]);
    Analyzer      a       = alert.getAnalyzer();
    
    if (a != null) {
      IDMEF_Node    node    = a.getNode();
      IDMEF_Process process = a.getProcess();
      
      User user = null;
      UserId uid1 = null;
      UserId uid2 = null;
      int uidCount = 0;
      if (userName1 != null) {
        uid1 = new UserId( userName1, null, null, UserId.TARGET_USER );
        uidCount++;
      }
      if (userName2 != null) {
        uid2 = new UserId( userName2, null, null, UserId.TARGET_USER );
        uidCount++;
      }
      if (uidCount > 0) {
        UserId uids[] = new UserId[uidCount];
        if (uid2 != null) {
          uids[--uidCount] = uid2;
        }
        if (uid1 != null) {
          uids[--uidCount] = uid1;
        }
        user = new User( uids, null, User.UNKNOWN );
      }
      Target t = new Target(node, user, process, null, null, null,
                            Target.UNKNOWN, null);
      alert.setTargets( new Target[] {t} );
    }

    NewEvent event = _cmrFactory.newEvent(alert);

    boolean close = true;
    try {
      close = _blackboardService.tryOpenTransaction();
    } catch (Exception e) {
      close = false;
    }
    try {
      _blackboardService.publishAdd(event);
      if (close) {
        _blackboardService.closeTransaction();
      }
   } catch (Exception e) {
   }
  }

  public long currentTimeMillis() { return System.currentTimeMillis(); }

  public String getBlackboardClientName() {
    return "KeyRingJNDIRealm";
  }

  public boolean triggerEvent(Object event) {
    return false;
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
