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
import java.util.Map;
import java.util.Set;
import java.text.SimpleDateFormat;
import java.text.DateFormat;

import java.security.Principal;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.NoSuchAlgorithmException;

import org.apache.catalina.Container;
import org.apache.catalina.Valve;
import org.apache.catalina.realm.RealmBase;
import org.apache.catalina.core.ContainerBase;

// IDMEF
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.DetectTime;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.IDMEF_Process;
import edu.jhuapl.idmef.Service;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.User;
import edu.jhuapl.idmef.UserId;
import edu.jhuapl.idmef.AdditionalData;

// Cougaar security infrastructure
import org.cougaar.core.security.acl.auth.DualAuthenticator;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;

// Cougaar core infrastructure
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.identity.*;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.services.acl.UserService;
import org.cougaar.core.security.services.acl.UserServiceException;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceAvailableEvent;

// Cougaar overlay
import org.cougaar.core.security.constants.IdmefClassifications;

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
 * <code>KeyRingJNDIRealm</code> uses the <code>UserService</code>
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

  private static ServiceBroker _serviceBroker;
  private static String        _realmName = "Cougaar";
  private LoggingService log;

  private static final DateFormat LDAP_TIME =
    new SimpleDateFormat("yyyyMMddHHmmss'Z'");
  private static final TimeZone   GMT = TimeZone.getTimeZone("GMT");

  private String                     _certComponent = "CN";
  private UserService                _userService;

  private static BlackboardService   _blackboardService;
  private static IdmefMessageFactory _idmefFactory;
  private static CmrFactory          _cmrFactory;
  private static SensorInfo          _sensor;
  private Hashtable                  _servers = new Hashtable();

  public static final int    LF_USER_DOESNT_EXIST       = 0;
  public static final int    LF_LDAP_ERROR              = 1;
  public static final int    LF_CERTIFICATE_INVALID     = 2;
  public static final int    LF_BAD_CERTIFICATE_SUBJECT = 3;
  public static final int    LF_USER_DISABLED           = 4;
  public static final int    LF_LDAP_PASSWORD_NULL      = 5;
  public static final int    LF_PASSWORD_MISMATCH       = 6;
  public static final int    LF_REQUIRES_CERT           = 7;
  public static final int    LF_REQUIRES_ROLE           = 8;

  public static final String FAILURE_REASON = "LOGIN_FAILURE_REASON";
  public static final Classification LOGINFAILURE = 
    new Classification(IdmefClassifications.LOGIN_FAILURE, "", Classification.VENDOR_SPECIFIC);

  public static final String FAILURE_REASONS[] = {
    "USER_DOES_NOT_EXIST",
    "DATABASE_ERROR",
    "INVALID_USER_CERTIFICATE",
    "INVALID_SUBJECT",
    "DISABLED_ACCOUNT",
    "NULL_DB_PASSWORD",
    "WRONG_PASSWORD",
    "CERTIFICATE_REQUIRED",
    "INSUFFICIENT_PRIVILEGES"};

  /** 
   * Default constructor. Uses <code>UserService</code>
   * given in the setDefaultLdapUserService call.
   */
  public KeyRingJNDIRealm() {
  }

  private synchronized boolean init() {
    if (_userService == null) {
      if (_serviceBroker == null) {
        return false;
      }
      _userService = (UserService) _serviceBroker.
        getService(this, UserService.class, null);
      if (_userService == null) {
        _serviceBroker.addServiceListener(new UserServiceListener());
      }
    }
    if (log == null) {
      log = (LoggingService)
        _serviceBroker.getService(this, LoggingService.class, null);
    }
    return true;
  }

  /**
   * Sets the default UserService using the node service broker
   */
  public static void setNodeServiceBroker(ServiceBroker sb) {
    _serviceBroker = sb;
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
    if (!init() || username == null || credentials == null) {
      // don't alert that there was no credentials -- that happens
      // under normal opera1tion
      return null;
    }
    try {
      Map attrs = _userService.getUser(username);
      if (!passwordOk(username, credentials, attrs)) {
        return null;
      }
      return getPrincipal(attrs);
    } catch (UserServiceException e) {
      setLoginError(LF_LDAP_ERROR, username, e);
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
        if (debug >= 2) super.log("  Validity exception", e);
        setLoginError(LF_CERTIFICATE_INVALID, null, e);
        return null;
      }
    }

    String userdn = certs[0].getSubjectDN().getName();

    String user = getUserName(userdn);
    if (user == null) {
      // certificate is bad, bad, bad!
      setLoginError(LF_BAD_CERTIFICATE_SUBJECT, userdn, null);
      return null;
    }

    try {
//       log.debug("Getting attributes for user: " + user);
      Map attrs = _userService.getUser(user);
      if (attrs == null) {
        setLoginError(LF_USER_DOESNT_EXIST, user, null);
        return null; // user isn't in the database
      }
      if (!userDisabled(attrs, true)) {
        return getPrincipal(attrs);
      } else {
        setLoginError(LF_USER_DISABLED, user, null);
      }
    } catch (UserServiceException ne) {
      setLoginError(LF_LDAP_ERROR, user, ne);
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
      Map userAttrs = _userService.getUser(username);
      Object pwdVal = userAttrs.get(_userService.getPasswordAttribute());
      if (pwdVal == null) {
        setLoginError(LF_LDAP_PASSWORD_NULL, username, null);
        return null;
      }
      String md5a1;
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
      
      setLoginError(LF_PASSWORD_MISMATCH, username, null);
    } catch (UserServiceException ne) {
      setLoginError(LF_LDAP_ERROR, username, ne);
    }
    return null;
  }

  public Principal updateUser(Principal principal) {
    if (!init()) return null;
    try {
      if (!(principal instanceof CougaarPrincipal)) {
        return null; // I don't believe you!
      }
      Map attrs = _userService.getUser(principal.getName());
      return getPrincipal(attrs);
    } catch (UserServiceException e) {
      setLoginError(LF_LDAP_ERROR, principal.getName(), e);
      return null;
    }
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
  protected Principal getPrincipal(Map userAttr) {
    String username = null;
    String authFields = "EITHER";
    if (_userService == null) return null;
    username = (String) userAttr.get(_userService.getUserIDAttribute());
    String authAttr = (String) 
      userAttr.get(_userService.getAuthFieldsAttribute());
    if (authAttr != null) {
      authFields = authAttr;
    }
    Set roles = (Set) userAttr.get(_userService.getRoleListAttribute());
    if (log.isDebugEnabled()) {
      log.debug("Got roles for " + username + ": " + roles);
    }
    return new CougaarPrincipal(this, username, new ArrayList(roles), 
                                authFields);
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
                               Map attrs)
    throws UserServiceException {
    boolean match = false;
    if (attrs == null) {
      setLoginError(LF_USER_DOESNT_EXIST, username, null);
      return false;
    }

    if (userDisabled(attrs, false)) {
      setLoginError(LF_USER_DISABLED, username, null);
      return false;
    }
    Object attrVal = attrs.get(_userService.getPasswordAttribute());
//     log.debug("attrVal = " + attrVal);
    if (attrVal == null) {
      setLoginError(LF_LDAP_PASSWORD_NULL, username, null);
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
      setLoginError(LF_PASSWORD_MISMATCH, username, null);
    }
    // in the future log a password match failure in a finally block
    return match;
  }

  /**
   * Returns true if the user account has been disabled. if the
   * account password is disabled, but the certIsSpecial field
   * in the user database is true, then the user is granted access
   * when the certificate is used.
   */
  private boolean userDisabled(Map attrs, boolean isCertAuth)
    throws UserServiceException {
    if (isCertAuth) {
      Object attrVal = attrs.get(_userService.getCertOkAttribute());
      if (attrVal != null) {
        if (Boolean.valueOf(attrVal.toString()).booleanValue()) {
          return false; // user is granted special certificate access
        } 
      } // end of if (attrVal != null)
    } // end of if (isCertAuth)
    
    Object attrVal = attrs.get(_userService.getEnableTimeAttribute());
    if (attrVal != null) {
      String val = attrVal.toString();
      Calendar now = Calendar.getInstance(GMT);
      String nowStr = LDAP_TIME.format(now.getTime());
      if (nowStr.compareToIgnoreCase(val) >= 0) {
        return false;
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
	  log.warn("Unable to open blackboard transaction: " + e);
        }
        _blackboardService.publishAdd(regEvent);
        try {
          if (close) _blackboardService.closeTransaction();
        } catch (Exception e) {
	  log.warn("Unable to close blackboard transaction: " + e);
        }
      }
    }
    } catch (Exception e) {
      log.warn("Unable to initialize Alert:" + e);
    }
    return (_idmefFactory != null);
  }

  private List createClassifications() {
    ArrayList cfs = new ArrayList();
    cfs.add(LOGINFAILURE);
    return cfs;
  }

  private List createSources(String remoteAddr) {
    List addrs = new ArrayList();
    Address addr = _idmefFactory.createAddress( remoteAddr, null,
                                                Address.IPV4_ADDR );
    addrs.add(addr);
    IDMEF_Node node = _idmefFactory.createNode( null, addrs );

    Source src = _idmefFactory.createSource(node, null, null, null, null);

    List srcs = new ArrayList();
    srcs.add(src);
    return srcs;
  }

  private List createTargets(String url, int serverPort, String protocol,
                             String userName) {
    IDMEF_Node node = _idmefFactory.getNodeInfo();
    List addrs = new ArrayList();
    if (node.getAddresses() != null) {
      Address[] a = node.getAddresses();
      for (int i = 0; i < a.length; i++) {
        addrs.add(a[i]);
      } // end of for (int i = 0; i < a.length; i++)
    }

    addrs.add(_idmefFactory.createAddress(url, null, Address.URL_ADDR));
    
    node = _idmefFactory.createNode(node.getName(), addrs);

    IDMEF_Process process = _idmefFactory.getProcessInfo();
    Service service = _idmefFactory.createService("Cougaar Web Server", 
                                                  new Integer(serverPort),
                                                  protocol);
      
    User user = null;
    List uids = new ArrayList();
    if (userName != null) {
      uids.add(_idmefFactory.createUserId( userName ));
    }
    if (uids.size() > 0) {
      user = _idmefFactory.createUser( uids );
    }
    Target target = _idmefFactory.createTarget(node, user, process, service,
                                               null, null);
    List targets = new ArrayList();
    targets.add(target);
    return targets;
  }
  
  private List createAdditionalData(int failureType, String targetIdent,
                                    Exception e) {
    Agent agentinfo = _idmefFactory.getAgentInfo();
    String [] ref=null;
    if (agentinfo.getRefIdents()!=null) {
      String[] originalref=agentinfo.getRefIdents();
      ref=new String[originalref.length+1];
      System.arraycopy(originalref,0,ref,0,originalref.length);
      ref[originalref.length] = targetIdent;
    } else {
      ref=new String[1];
      ref[0] = targetIdent;
    }
    agentinfo.setRefIdents(ref);

    AdditionalData additionalData = 
      _idmefFactory.createAdditionalData(Agent.TARGET_MEANING, agentinfo);
    List addData = new ArrayList();
    addData.add(_idmefFactory.
                createAdditionalData(AdditionalData.STRING, FAILURE_REASON,
                                     FAILURE_REASONS[failureType]));
    addData.add(additionalData);
    if (e != null) {
      addData.add(_idmefFactory.
                  createAdditionalData(AdditionalData.STRING,
                                       "Exception", e.getMessage()));
    }
    return addData;
  }

  public void alertLoginFailure(int failureType, String userName, 
                                Exception ex,
                                String remoteAddr,
                                int serverPort, String protocol,
                                String url) {
    if (!isAlertInitialized()) {
      log.debug("Couldn't alert about " + 
                         FAILURE_REASONS[failureType] +
                         ", userName: " + userName);
      return; // can't alert without IDMEF factory
    }

    List sources = createSources(remoteAddr);
    List targets = createTargets(url, serverPort, protocol,
                                 userName);
    List classifications = createClassifications();
    String targetIdent = ((Target) targets.get(0)).getIdent();
    List additionalData = createAdditionalData(failureType, targetIdent, ex);
    Alert alert = _idmefFactory.createAlert(_sensor, new DetectTime(),
                                            sources, targets,
                                            classifications,
                                            additionalData);
    
    NewEvent event = _cmrFactory.newEvent(alert);
    
    try {
      _blackboardService.openTransaction();
      _blackboardService.publishAdd(event);
      _blackboardService.closeTransaction();
    } catch (Exception e) {
      log.warn("Unable to publish alert login failure to the blackboard:" + e);
    }
  }

  public long currentTimeMillis() { return System.currentTimeMillis(); }

  public String getBlackboardClientName() {
    return "KeyRingJNDIRealm";
  }

  public boolean triggerEvent(Object event) {
    return false;
  }

  private void setLoginError(int err, String userName, Exception e) {
    log.info("Login failed for " + userName + " . Reason:" + FAILURE_REASONS[err]);
    ServerInfo info = (ServerInfo) _servers.get(Thread.currentThread());

    alertLoginFailure(err, userName, e, info.remoteAddr, info.serverPort,
                      info.protocol, info.url);
  }

  public void setServer(String remoteAddr, int serverPort, String protocol,
                        String url) {
    ServerInfo si = new ServerInfo();
    si.remoteAddr = remoteAddr;
    si.serverPort = serverPort;
    si.protocol = protocol;
    si.url = url;
    _servers.put(Thread.currentThread(), si);
  }

  public void clearServer() {
    _servers.remove(Thread.currentThread());
  }

  static class ServerInfo {
    public String remoteAddr;
    public int serverPort;
    public String protocol;
    public String url;
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

  private class UserServiceListener implements ServiceAvailableListener {
    public final String USER_SERVICE_NAME = UserService.class.getName();
    public void serviceAvailable(ServiceAvailableEvent ae) {
      if (ae.getService().equals(USER_SERVICE_NAME)) {
        _userService = (UserService) ae.getServiceBroker().
           getService(this, UserService.class, null);
        if (_userService != null) {
          ae.getServiceBroker().removeServiceListener(this);
        }
      }
    }
  }

}
