/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 *
 * Created on September 12, 2001, 10:55 AM
 */

package org.cougaar.core.security.acl.auth;

import java.io.*;
import java.util.*;
import java.security.Principal;
import java.net.*;
import java.lang.reflect.*;
import javax.net.ssl.*;

import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.servlet.ServletOutputStream;

import org.apache.catalina.Session;
import org.apache.catalina.Request;
import org.apache.catalina.Response;
import org.apache.catalina.Context;
import org.apache.catalina.Container;
import org.apache.catalina.ValveContext;
import org.apache.catalina.HttpRequest;
import org.apache.catalina.HttpResponse;
import org.apache.catalina.Realm;
import org.apache.catalina.Manager;
import org.apache.catalina.valves.ValveBase;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.deploy.SecurityCollection;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.authenticator.SSLAuthenticator;
import org.apache.catalina.authenticator.DigestAuthenticator;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.connector.HttpResponseWrapper;


import org.cougaar.core.service.LoggingService;
import org.cougaar.lib.web.tomcat.SecureRealm;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.ldap.CougaarPrincipal;
import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;
import org.cougaar.core.security.provider.ServletPolicyServiceProvider;
import org.cougaar.core.security.policy.enforcers.ServletNodeEnforcer;
import org.cougaar.core.security.policy.enforcers.util.AuthSuite;

public class DualAuthenticator extends ValveBase {
  static final byte AUTH_NONE     = AuthSuite.authNoAuth;
  static final byte AUTH_PASSWORD = AuthSuite.authPassword;
  static final byte AUTH_CERT     = AuthSuite.authCertificate;
  static final byte AUTH_NEVER    = AuthSuite.authInvalid;

  private static ResourceBundle _authenticators = null;
  private ServletNodeEnforcer _enforcer;
  AuthenticatorBase _primaryAuth;
  AuthenticatorBase _secondaryAuth;
  LoginConfig       _loginConfig = new LoginConfig();
  Context           _context     = null;
  HashMap           _constraints = new HashMap();
  HashMap           _starConstraints = new HashMap();
  long              _failSleep   = 1000;
  long              _sessionLife = 60000;
  ServiceBroker     _serviceBroker;
  LoggingService    _log;

  public static final String DAML_PROPERTY = 
    "org.cougaar.core.security.policy.enforcers.servlet.useDaml";
  private static final boolean USE_DAML = Boolean.getBoolean(DAML_PROPERTY);

  public DualAuthenticator() {
    this(new SSLAuthenticator(), new BasicAuthenticator());
  }

  public DualAuthenticator(AuthenticatorBase secondaryAuth) {
    this(new SSLAuthenticator(), secondaryAuth);
  }

  public DualAuthenticator(AuthenticatorBase primaryAuth,
                           AuthenticatorBase secondaryAuth) {
    try {
      setPrimaryAuthenticator(primaryAuth);
      setSecondaryAuthenticator(secondaryAuth);
      ServletPolicyServiceProvider.setDualAuthenticator(this);
    } catch (Exception e) {
      _log.error("Error starting Servlet Authenticator", e);
    }
  }

  public void setServiceBroker(ServiceBroker sb) {
    _serviceBroker = sb;
    _log = (LoggingService) sb.getService(this, LoggingService.class, null);
  }

  private boolean initNodeEnforcer() {
    try {
      if (USE_DAML && _enforcer == null && _serviceBroker != null) {
        _log.debug("Creating ServletNodeEnforcer");
        ServletNodeEnforcer enforcer = new ServletNodeEnforcer(_serviceBroker);
        _log.debug("Registering ServletNodeEnforcer");
        enforcer.registerEnforcer();
        _log.debug("Done registering ServletNodeEnforcer");
        _enforcer = enforcer;
      }
      return true;
    } catch (Exception e) {
      _log.warn("Error registerring Servlet Node Enforcer", e);
      return false;
    }
  }

  /**
   * Valve callback. First check the primary authentication method
   * and if not authenticated, call the secondary authentication method.
   */
  public void invoke(Request request, Response response,
                     ValveContext context) 
    throws IOException, ServletException {

    setContainer();

    _log.debug("Going through Dual Authenticator");
    // If this is not an HTTP request, do nothing
    if (!(request instanceof HttpRequest) ||
        !(response instanceof HttpResponse)) {
      context.invokeNext(request, response);
      return;
    }
    if (!(request.getRequest() instanceof HttpServletRequest) ||
        !(response.getResponse() instanceof HttpServletResponse)) {
      context.invokeNext(request, response);
      return;
    }
    try {
    HttpRequest hrequest = (HttpRequest) request;
    HttpResponse hresponse = (HttpResponse) response;
    HttpServletRequest  hsrequest  = (HttpServletRequest) request.getRequest();
    HttpServletResponse hsresponse = 
      (HttpServletResponse) request.getResponse();

    if (!initNodeEnforcer()) {
      // nobody can access any servlet until the node enforcer is ready
      hsresponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                           "Please wait for Servlet enforcement to become available.");
      return;
    }

    String cipher = getCipher(hrequest);

    // this is only for DAML (efficiency -- only ask once and use in
    // two calls...)
    AuthSuite authReq = 
      getAuthRequirements(hsrequest.getRequestURI(), cipher);

    if (_log.isDebugEnabled()) {
      _log.debug("cipher = " + cipher);
    }
    // determine if we need to redirect to HTTPS
    if (!hsrequest.isSecure() && 
        needHttps(hsrequest, cipher, authReq)) {
      _log.debug("moving over to https");
      redirectToHttps(hrequest, hresponse, hsrequest, hsresponse);
      return;
    }

    // determine the authentication requirement for this URI
    byte uriAuthLevel = 
      getURIAuthRequirement(hsrequest.getRequestURI(), cipher, authReq);
    byte userAuthLevel;

    if (_log.isDebugEnabled()) {
      _log.debug("URI requires " + uriAuthLevel);
    }
    if (uriAuthLevel == AUTH_NEVER) {
      _log.debug("no user may access this servlet");
      hsresponse.sendError(HttpServletResponse.SC_FORBIDDEN,
                           hsrequest.getRequestURI());
      return;
    }
    if (uriAuthLevel == AUTH_NONE) {
      // no authentication requirement
      _log.debug("no authorization.. invoking servlet");
      context.invokeNext(request, response);
      return;
    }
    
    // determine if the principal is already cached
    Principal principal =  getCachedPrincipal(hrequest, hsrequest);
    userAuthLevel = getAuthLevel(hsrequest.getAuthType());

    if (_log.isDebugEnabled()) {
      _log.debug("User auth level: " + userAuthLevel);
    }
    if (principal == null || userAuthLevel < uriAuthLevel) {
      // The authentication level is not enough. 
      _log.debug("Authenticate the user");
      principal = authenticate(hrequest, hresponse, 
                               hsrequest, hsresponse, uriAuthLevel);
      if (_log.isDebugEnabled()) {
        _log.debug("Authenticated the user: " + principal);
      }
      if (principal == null) {
        failSleep();
        return; // couldn't authenticate
      }
      userAuthLevel = getAuthLevel(hsrequest.getAuthType());
    }
    if (_log.isDebugEnabled()) {
      _log.debug("User auth level: " + userAuthLevel);
    }
    // we're authenticate, now check the roles
    if (rolesOk(cipher, userAuthLevel, 
                (CougaarPrincipal) principal, hsrequest)) {
      _log.debug("roles are good... invoking servlet");
      // authorization is ok
      context.invokeNext(request, response);
    } else {
      alertAuthorizationFailure(hsrequest, principal);
      failSleep();
      _log.debug("roles are bad... returning error");
      hsresponse.sendError(HttpServletResponse.SC_FORBIDDEN,
                           hsrequest.getRequestURI());
    }
    } catch (Throwable t) {
      t.printStackTrace();
    }
  }

  private void alertAuthorizationFailure(HttpServletRequest req, 
                                         Principal user) {
    String userName = "<no name>";
    if (user != null) {
      userName = user.getName();
    }
    getRealm().alertLoginFailure(KeyRingJNDIRealm.LF_REQUIRES_ROLE,
                                 userName, null /* exception */,
                                 req.getRemoteAddr(), req.getServerPort(),
                                 req.isSecure() ? "https" : "http",
                                 req.getRequestURL().toString());
  }

  private static String getCipher(HttpRequest req) {
    Socket sock = req.getSocket();
    if (!(sock instanceof SSLSocket)) {
      return "plain";
    }

    SSLSocket ssl = (SSLSocket) sock;
    return ssl.getSession().getCipherSuite();
  }

  protected boolean authenticate(AuthenticatorBase auth, 
                                 HttpRequest req, HttpResponse resp) 
    throws IOException {
    if (auth instanceof SSLAuthenticator) {
      return ((SSLAuthenticator) auth).authenticate(req, resp, _loginConfig);
    } 
    if (auth instanceof BasicAuthenticator) {
      return ((BasicAuthenticator) auth).authenticate(req, resp, _loginConfig);
    } 
    if (auth instanceof DigestAuthenticator) {
      return ((DigestAuthenticator) auth).authenticate(req, resp, _loginConfig);
    }

    try {
      Method method =  
        auth.getClass().getMethod("authenticate", new Class[] { 
          HttpRequest.class, HttpResponse.class, LoginConfig.class });
      return ((Boolean) method.invoke(auth, new Object[] { 
        req, resp, _loginConfig })).booleanValue();
    } catch (Exception e) {
      return false;
    }
  }

  protected boolean rolesOk(String cipher, byte userAuthLevel,
                            CougaarPrincipal principal,
                            HttpServletRequest req) {
    if (USE_DAML) {
      String roles[] = principal.getRoles();
      HashSet roleSet = new HashSet();
      for (int i = 0; i < roles.length; i++) {
        roleSet.add(roles[i]);
      }
      return _enforcer.isActionAuthorized(roleSet, 
                                          req.getRequestURI(),
                                          cipher, userAuthLevel);
                                          
    }
    SecurityConstraint constraint = findConstraint(req.getRequestURI());
    if (constraint == null) {
      return true;
    }

    if (constraint.getAllRoles()) {
      return true;
    }

    Realm realm = getRealm();
    String roles[] = constraint.findAuthRoles();
    if (roles != null) {
      for (int i = 0; i < roles.length; i++) {
        if (realm.hasRole(principal, roles[i])) {
          return true;
        }
      }
    }
    return false;
  }

  protected byte getAuthLevel(String auth) {
    if (_log.isDebugEnabled()) {
      _log.debug("Converting authorization level: " + auth);
      /*
      _log.debug("auth levels: " + HttpServletRequest.BASIC_AUTH +
                 " " + HttpServletRequest.DIGEST_AUTH + " " +
                 HttpServletRequest.FORM_AUTH + " " + 
                 HttpServletRequest.CLIENT_CERT_AUTH);
      */
    }
    if (HttpServletRequest.BASIC_AUTH.equals(auth) ||
        HttpServletRequest.DIGEST_AUTH.equals(auth) ||
        HttpServletRequest.FORM_AUTH.equals(auth)) {
      return AUTH_PASSWORD;
    }
    if (HttpServletRequest.CLIENT_CERT_AUTH.equals(auth) ||
        org.apache.catalina.authenticator.Constants.CERT_METHOD.equals(auth)) {
      return AUTH_CERT;
    }
    if (auth == null) {
      return AUTH_NONE;
    }

    // EITHER and BOTH are legacy terms
    if ("PASSWORD".equals(auth) || "EITHER".equals(auth)) {
      return AUTH_PASSWORD;
    } else if ("CERT".equals(auth) || "BOTH".equals(auth)) {
      return AUTH_CERT;
    } else if ("NONE".equals(auth)) {
      return AUTH_NONE;
    }

    if (auth.equals(HttpServletRequest.BASIC_AUTH) ||
        auth.equals(HttpServletRequest.DIGEST_AUTH) ||
        auth.equals(HttpServletRequest.FORM_AUTH)) {
      return AUTH_PASSWORD;
    }
    if (auth.equals(HttpServletRequest.CLIENT_CERT_AUTH)) {
      return AUTH_CERT;
    }
    return AUTH_NONE;
  }

  protected SecurityConstraint findConstraint(String uri) {
      
    // Are there any defined security constraints?
    SecurityConstraint constraints[] = _context.findConstraints();
    if ((constraints == null) || (constraints.length == 0)) {
      return null;
    }

    try {
      uri = URLDecoder.decode(uri, "UTF-8"); // Before checking constraints
    } catch (UnsupportedEncodingException e) {
      // leave the uri as is and pray
      if (_log.isDebugEnabled()) {
        _log.debug("Unsupported URL encoding: " + uri);
      }
    }
    for (int i = 0; i < constraints.length; i++) {
      if (constraints[i].included(uri, "GET"))
        return constraints[i];
    }
    return null;
  }

  protected byte getURIAuthRequirement(String path, String cipher, 
                                       AuthSuite cwa) {
    if (USE_DAML) {
      if (cwa == null) {
        // don't bother authenticating when you already know you can't reach it
        return AUTH_NEVER; 
      }
      int authType = cwa.getAuth();
      if (_log.isDebugEnabled()) {
        _log.debug("using URI constraint: " + authType);
      }
      // now we only care about the least auth requirement...
      if ((authType & cwa.authNoAuth) != 0) {
        return AUTH_NONE;
      } else if ((authType & cwa.authPassword) != 0) {
        return AUTH_PASSWORD;
      } else if ((authType & cwa.authCertificate) != 0) {
        return AUTH_CERT;
      } else {
        return AUTH_NEVER;
      }
    }
    HashMap checkAgainst = _constraints;
    byte constraint = AUTH_NONE;
    do {
      Iterator iter = checkAgainst.entrySet().iterator(); 
      while (iter.hasNext()) {
        Map.Entry entry = (Map.Entry) iter.next();
        String wildPath = (String) entry.getKey();
        if (_log.isDebugEnabled()) {
          _log.debug("Checking " + path + " against " + wildPath);
        }
        boolean match = checkMatch(path, wildPath);
        
        if (match) {
          String type = (String) entry.getValue();
          constraint = getAuthLevel(type);
          if (_log.isDebugEnabled()) {
            _log.debug("constraint = " + constraint + " from " + type);
          }
          if (constraint == AUTH_CERT) {
            return constraint;
          }
        }
      }
      
      if (checkAgainst == _starConstraints) {
        return constraint; // only go through twice
      }

      int index = 0;
      if (!path.startsWith("/$") || (index = path.indexOf("/", 2)) == -1) {
        return constraint;
      }
      path = path.substring(index);
      checkAgainst = _starConstraints;
    } while (true);
  }
  /*
  private static String uriToPath(String uri) {
    if (!uri.startsWith("/$")) {
      return uri;
    }
    int index = uri.indexOf("/", 2);
    if (index == -1) { 
      return uri;
    }
    return uri.substring(index);
  }
  */
  private AuthSuite getAuthRequirements(String uri, String cipher) {
    if (USE_DAML) {
      return _enforcer.whichAuthSuite(uri);
    }
    return null;
  }

  protected boolean needHttps(HttpServletRequest req, String cipher, 
                              AuthSuite cwa) {
    if (USE_DAML) {
      if (cwa == null || cwa.getAuth() == cwa.authInvalid) {
        return false;
      }
      return !(cwa.getSSL().contains("plain"));
      /*
      int authReq = cwa.getAuth();
      return ((authReq & cwa.authPassword) == 0 && 
              (authReq & cwa.authNoAuth) == 0);
      */
    }
    SecurityConstraint constraint = findConstraint(req.getRequestURI());
    if (constraint == null) {
      return false;
    }
    String userConstraint = constraint.getUserConstraint();
    if (userConstraint == null) {
      return false;
    }
    if (userConstraint.equals(org.apache.catalina.authenticator.Constants.NONE_TRANSPORT)) {
      return false;
    }
    if (req.isSecure()) {
      return false;
    }
    return true;
  }

  protected void redirectToHttps(HttpRequest req, HttpResponse resp,
                                 HttpServletRequest hrequest, 
                                 HttpServletResponse hresponse)
    throws IOException {
    int redirectPort = req.getConnector().getRedirectPort();
    if (redirectPort <= 0) {
      hresponse.sendError(HttpServletResponse.SC_FORBIDDEN,
                          hrequest.getRequestURI());
      return;
    }

    // Redirect to the corresponding SSL port
    String protocol = "https";
    String host = hrequest.getServerName();
    StringBuffer file = new StringBuffer(hrequest.getRequestURI());
    String requestedSessionId = hrequest.getRequestedSessionId();
    if ((requestedSessionId != null) &&
        hrequest.isRequestedSessionIdFromURL()) {
      file.append(";jsessionid=");
      file.append(requestedSessionId);
    }
    String queryString = hrequest.getQueryString();
    if (queryString != null) {
      file.append('?');
      file.append(queryString);
    }

    URL url = null;
    try {
      url = new URL(protocol, host, redirectPort, file.toString());
      hresponse.sendRedirect(url.toString());
    } catch (MalformedURLException e) {
      hresponse.sendError
        (HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
         hrequest.getRequestURI());
    }
  }

  protected void failSleep() {
    try {
      Thread.sleep(_failSleep);
    } catch (Exception e) {
      if (_log.isWarnEnabled()) {
        _log.warn("Thread interrupted: " + e.toString());
      }
    }
  }

  protected KeyRingJNDIRealm getRealm() {
    Realm rlm = _context.getRealm();
    if (rlm instanceof SecureRealm) {
      SecureRealm srealm = (SecureRealm) _context.getRealm();
      return (KeyRingJNDIRealm) srealm.getRealm();
    }
    return (KeyRingJNDIRealm) rlm;
  }

  protected Principal authenticate(HttpRequest req, HttpResponse resp,
                                   HttpServletRequest hreq, 
                                   HttpServletResponse hresp,
                                   byte uriAuthLevel) throws IOException {
    KeyRingJNDIRealm realm = getRealm();
    try {
      realm.setServer(hreq.getRemoteAddr(), hreq.getServerPort(),
                      hreq.isSecure() ? "https" : "http", 
                      hreq.getRequestURL().toString());

      HttpResponse sslResponse = resp;
      if (uriAuthLevel == AUTH_PASSWORD) {
        sslResponse = new ResponseDummy(resp, new NoErrorResponse(hresp));
      }

      // first try SSL authentication
      boolean authed = authenticate(_primaryAuth, req, sslResponse);
      if (!authed) {
        _log.debug("Could not authenticate with SSL");
        // not CERT authed
        if (uriAuthLevel == AUTH_CERT) {
          return null; // returned error already
        }

        // try password
        authed = authenticate(_secondaryAuth, req, resp);
        if (!authed) {
          _log.debug("Could not authenticate with password");
        } else {
          _log.debug("Authenticated with password");
          // check the user requirements
          CougaarPrincipal principal = 
            (CougaarPrincipal) hreq.getUserPrincipal();
          byte userAuthRequirements = 
            getAuthLevel(principal.getLoginRequirements());

          if (userAuthRequirements == AUTH_CERT) {
            if (hreq.isSecure()) {
              // I know it will return an error
              authenticate(_primaryAuth, req, resp);
            } else {
              // redirect to Https
              redirectToHttps(req, resp, hreq, hresp);
            }
            return null;
          }
        }
      }
      return hreq.getUserPrincipal();
    } finally {
      realm.clearServer();
    }
  }

  protected Principal getCachedPrincipal(HttpRequest hreq,
                                         HttpServletRequest req) {
    Principal principal = req.getUserPrincipal();
    HttpSession session = req.getSession(false);
    Session sn = null;
    if (session != null) {
      Manager manager = _context.getManager();
      if (manager != null) {
        try {
          sn = manager.findSession(session.getId());
          if (sn != null && principal == null) {
            principal = sn.getPrincipal();
            hreq.setAuthType(sn.getAuthType());
            hreq.setUserPrincipal(principal);
          }
        } catch (IOException e) {
          // just return null
          if (_log.isWarnEnabled()) {
            _log.warn("Unable to find session: " + e.toString());
          }
        }
      }
    }
    if (session != null && principal != null) {
      long now = System.currentTimeMillis();
      if (now - session.getCreationTime() > _sessionLife) {
        principal = getRealm().updateUser(principal);
        if (principal == null) {
          hreq.setUserPrincipal(null);
          hreq.setAuthType(null);
        }
      }
      return principal;
    }
    return null;
  }

  /**
   * Valve callback. First check the primary authentication method
   * and if not authenticated, call the secondary authentication method.
   */
  /*
  public void invoke(Request request, Response response,
                     ValveContext context) throws IOException, ServletException {
    // ensure that authentication containers are set
    setContainer(); 

    // create dummies so that authentication doesn't do anything
    // we really do want it to do
    DummyValveContext  dummyValveContext = new DummyValveContext();
    HttpServletResponse no_err =
      new NoErrorResponse((HttpServletResponse) response.getResponse());
    ResponseDummy tmpRes = 
      new ResponseDummy((HttpResponse) response, no_err);

    HttpServletRequest hreq = (HttpServletRequest) request.getRequest();
    HttpServletResponse hres = (HttpServletResponse) request.getResponse();
    boolean certInvoked;
    boolean passInvoked;

    int userConstraint = CONST_NONE;
    int pathConstraint = getConstraint(hreq.getRequestURI());

    String remoteAddr = hreq.getRemoteAddr();
    int serverPort = hreq.getServerPort();
    Realm realm = _context.getRealm();
    if (realm instanceof SecureRealm) {
      realm = ((SecureRealm) realm).getRealm();
    }
    KeyRingJNDIRealm krjr = null;
    if (realm instanceof KeyRingJNDIRealm) {
      krjr = (KeyRingJNDIRealm) realm;
    } // end of if (realm instanceof KeyRingJNDIRealm)
    
    String protocol = ( hreq.isSecure() ?
                        "https" :
                        "http" );
    String url = hreq.getRequestURL().toString();

    _primaryAuth.invoke(request,tmpRes, dummyValveContext);
    
    Principal certPrincipal = hreq.getUserPrincipal();
    Principal passPrincipal = null;
    Object    certError[]   = null;
    Object    passError[]   = null;
    if (krjr != null) {
      certError = krjr.getLoginError();
    } // end of if (krjr != null)
    
    if (certPrincipal instanceof CougaarPrincipal) {
      userConstraint = convertConstraint( ((CougaarPrincipal)certPrincipal).
                                          getLoginRequirements() );
      if ( (userConstraint & CONST_PASSWORD) != 0 ) {
        ((HttpRequest)request).setUserPrincipal(null);
      }
    }

    certInvoked = (dummyValveContext.getInvokeCount() > 0);
    dummyValveContext.resetInvokeCount();
    int totalConstraint = pathConstraint | userConstraint;

    if (totalConstraint == CONST_NONE || 
        (certPrincipal == null && (totalConstraint & CONST_CERT) != 0)  || 
        (totalConstraint & CONST_PASSWORD) != 0) {
      _secondaryAuth.invoke(request, response, dummyValveContext);
      passPrincipal = hreq.getUserPrincipal();
      if (krjr != null) {
        passError = krjr.getLoginError();
      } // end of if (krjr != null)
      if (certPrincipal == null && 
          passPrincipal instanceof CougaarPrincipal) {
        userConstraint = convertConstraint(((CougaarPrincipal)passPrincipal).
                                           getLoginRequirements() );
        totalConstraint = pathConstraint | userConstraint;
      }
    }

    passInvoked = (dummyValveContext.getInvokeCount() > 0);

    if (authOk(certPrincipal, passPrincipal, totalConstraint, 
               certInvoked, passInvoked, hres, krjr, remoteAddr,
               serverPort, protocol, url, certError, passError)) {
      context.invokeNext(request,response);
      return;
    } else if (certPrincipal != null) {
      // certificate authentication ok, so we really believe they
      // are who they say they are.
      return;
    }

    try {
      Thread.sleep(_failSleep);
    } catch (InterruptedException e) {
      // no sweat
    }
  }

  private static boolean authOk(Principal certPrincipal,
                                Principal passPrincipal,
                                int totalConstraint,
                                boolean certInvoked,
                                boolean passInvoked,
                                HttpServletResponse hres,
                                KeyRingJNDIRealm realm, String remoteAddr,
                                int serverPort, String protocol,
                                String url, 
                                Object[] certError,
                                Object[] passError) 
    throws ServletException, IOException {
          if (_log.isDebugEnabled()) {
//     _log.debug("certPrincipal:   " + certPrincipal);
//     _log.debug("passPrincipal:   " + passPrincipal);
//     _log.debug("totalConstraint: " + totalConstraint);
//     _log.debug("certInvoked:     " + certInvoked);
//     _log.debug("passInvoked:     " + passInvoked);
}

    if (certPrincipal != null && passPrincipal != null &&
        !certPrincipal.getName().equals(passPrincipal.getName())) {
      // the certificate and password authorization credentials
      // should be the same!
      hres.sendError(hres.SC_UNAUTHORIZED,
                     "You have entered a different user name than " +
                     "in your certificate.");
      sendFailureMessage(realm, KeyRingJNDIRealm.LF_USER_MISMATCH,
                         certPrincipal.getName(),
                         passPrincipal.getName(),
                         null,
                         remoteAddr, serverPort, protocol, url);
      return false;
    } else if ( ( certInvoked && passInvoked ) ||
                ( passInvoked && (totalConstraint & CONST_CERT) == 0 ) ||
                ( certInvoked && (totalConstraint & CONST_PASSWORD) == 0 ) ) {
      // ok, there is no role requirement so no authentication is
      // necessary.
//       _log.debug("no requirement");
      return true;
    } else if ( (totalConstraint & CONST_PASSWORD) != 0 &&
                passPrincipal == null) {
      // needed password authentication. We must have already
      // sent the bad response
      return false;
    } else if ((totalConstraint & CONST_CERT) != 0) {
      if (certPrincipal == null) {
        // needed certificate authentication. We need to send a response
        // indicating that:
        hres.sendError(hres.SC_UNAUTHORIZED,
                       "You must provide a client certificate in order " +
                       "to access this URL");
        String name = null;
        if (passPrincipal != null) {
          name = passPrincipal.getName();
        } else if (certError != null) {
          name = (String) certError[1];
        } else if (passError != null) {
          name = (String) passError[1];
        }           
        
        sendFailureMessage(realm,KeyRingJNDIRealm.LF_REQUIRES_CERT,
                           name, null, null,
                           remoteAddr, serverPort, protocol, url);
        return false;
      } else if (!certInvoked && !passInvoked) {
        hres.sendError(hres.SC_UNAUTHORIZED,
                       "You do not have the required role to access this URL");
        sendFailureMessage(realm, KeyRingJNDIRealm.LF_REQUIRES_ROLE,
                           certPrincipal.getName(), null, null,
                           remoteAddr, serverPort, protocol, url);
        return false;
      } else {
//         _log.debug("user is granted");
        return true; // user is granted access
      }
    } else if (!certInvoked && !passInvoked) {
      // nobody authenticated this user and therefore we must deny them.
      // the password authentication has already given a response.
      String name = null;
      int    errno = KeyRingJNDIRealm.LF_REQUIRES_ROLE;
      Exception e = null;
      if (certError != null) {
        name = (String) certError[1];
        errno = ((Integer) certError[0]).intValue();
        e = (Exception) certError[2];
      } else if (passError != null) {
        name = (String) passError[1];
        errno = ((Integer) passError[0]).intValue();
        e = (Exception) passError[2];
      } else if (certPrincipal != null) {
        name=certPrincipal.getName();
      } else if (passPrincipal != null) {
        name=passPrincipal.getName();
      }
      if (name != null) {
        sendFailureMessage(realm, errno, name, null, e,
                           remoteAddr, serverPort, protocol, url);
      }
      return false;
    } else {
      // authentication is accepted
//       _log.debug("user auth is accepted");
      return true;
    }
  }

  private static void sendFailureMessage(KeyRingJNDIRealm realm, 
                                         int messageID, 
                                         String user1, String user2, 
                                         Exception e,
                                         String remoteAddr, int serverPort,
                                         String protocol, String url) {
    if (realm != null) {
      realm.alertLoginFailure( messageID, user1, user2, e, remoteAddr,
                               serverPort, protocol, url);
    }    
  }
  */

  /**
   * Sets an authentication constraints. It allows
   * the specification of whether the path should support authentication
   * using certificates, password, both, or either. When checking
   * paths, a combination of the most restrictive constraints is used.
   * Therefore, if "/*" is given "EITHER" and "/$foo/*" is given
   * "PASSWORD", then PASSWORD is used as the constraint.<p>
   *
   * All constraints are replaced by the argument.
   *
   * @param constraints A map with the pattern as the key and the
   *                    constraint as the value. The constraint can be
   *                    "CERT" for certificate authentication, "PASSWORD" for
   *                    BASIC auth or DIGEST authentication, "BOTH"
   *                    to require both a certificate and proper password, and
   *                    "EITHER" to not have any password requirements beyond
   *                    what is required by the role-based constraints.
   */
  public synchronized void setAuthConstraints(Map constraints, 
                                              Map starConstraints) {
    _constraints = new HashMap(constraints);
    _starConstraints = new HashMap(starConstraints);
  }

  /**
   * Sets the time to sleep when a user has a login failure.
   */
  public synchronized void setLoginFailureSleepTime(long sleepTime) {
    _failSleep = sleepTime;
  }

  /**
   * Sets the maximum cached session life time (milliseconds) before
   * rechecking the user database.
   */
  public synchronized void setSessionLife(long sessionLife) {
    _sessionLife = sessionLife;
  }

  private static boolean checkMatch(String path, String wildPath) {
    if (wildPath.startsWith("*")) {
      return path.endsWith(wildPath.substring(1));
    } else if (wildPath.endsWith("*")) {
      return path.startsWith(wildPath.substring(0,wildPath.length()-1));
    } else {
      return path.equals(wildPath);
    }
  }

  private static AuthenticatorBase getAuthenticator(Class authClass) {
    try { 
      Object auth = authClass.newInstance();
      if (auth instanceof AuthenticatorBase) {
        return (AuthenticatorBase) auth;
      }
      throw new IllegalArgumentException("The Class " + 
                                         authClass.getName() + 
                                         " is not an Authenticator");
    } catch (IllegalAccessException e) {
      throw new IllegalArgumentException("You don't have access to Class " + 
                                         authClass.getName());
    } catch (InstantiationException e) {
      throw new IllegalArgumentException("Class " + 
                                         authClass.getName() + 
                                         " does not have a default constructor");
    }
  }

  private static AuthenticatorBase getAuthenticator(String authType) {
    // Load our mapping properties if necessary
    getResourceBundle();

    String authName = null;
    try {
      authName = _authenticators.getString(authType);
      return getAuthenticator(Class.forName(authName));
    } catch (MissingResourceException e) {
      throw new IllegalArgumentException("I don't know about the authenticator type: " +
                                         authType);
    } catch (ClassNotFoundException e) {
      throw new IllegalArgumentException("I can't find authenticator type (" + 
                                         authType + ") " + e);
    }
  }

  public void setPrimaryAuthenticator(AuthenticatorBase primaryAuth) {
    _primaryAuth = primaryAuth;
  }

  public void setSecondaryAuthenticator(AuthenticatorBase secondaryAuth) {
    _secondaryAuth = secondaryAuth;
  }

  public void setPrimaryAuthenticatorName(String primaryAuth) {
    setPrimaryAuthenticator(getAuthenticator(primaryAuth));
  }

  public void setSecondaryAuthenticatorName(String secondaryAuth) {
    setSecondaryAuthenticator(getAuthenticator(secondaryAuth));
  }

  public void setPrimaryAuthenticatorClass(Class primaryAuth) {
    setPrimaryAuthenticator(getAuthenticator(primaryAuth));
  }

  public void setSecondaryAuthenticatorClass(Class secondaryAuthClass) {
    setSecondaryAuthenticator(getAuthenticator(secondaryAuthClass));
  }

  public String getErrorPage() { return _loginConfig.getErrorPage(); }
  public void setErrorPage(String errorPage) {
    _loginConfig.setErrorPage(errorPage);
  }

  public String getLoginPage() { return _loginConfig.getLoginPage(); }
  public void setLoginPage(String loginPage) {
    _loginConfig.setLoginPage(loginPage);
  }

  public String getRealmName() { return _loginConfig.getRealmName(); }
  public void setRealmName(String realmName) {
    _loginConfig.setRealmName(realmName);
    KeyRingJNDIRealm.setRealmName(realmName);
  }

  public String getAuthMethod() { return _loginConfig.getAuthMethod(); }
  public void setAuthMethod(String authMethod) {
    _loginConfig.setAuthMethod(authMethod);
    setSecondaryAuthenticatorName(authMethod);
  }

  private synchronized void setContainer() {
    if (_context == null) {
      _context = (Context) getContainer();
      _primaryAuth.setContainer(_context);
      _secondaryAuth.setContainer(_context);
      _context.setLoginConfig(_loginConfig);
    }
  }

  private static synchronized void getResourceBundle() {
    if (_authenticators == null) {
      try {
        _authenticators = ResourceBundle.getBundle
          ("org.apache.catalina.startup.Authenticators");
      } catch (MissingResourceException e) {
        throw new IllegalStateException("Could not open Authenticators setup resource: " + e.getMessage());
      }
    }
  }

  private class ResponseDummy extends HttpResponseWrapper {
    HttpServletResponse _hres;
    HttpResponse        _resp;

    public ResponseDummy(HttpResponse resp, HttpServletResponse hres) {
      super(resp);
      _hres = hres;
      _resp = resp;
      
    }

    public ServletResponse getResponse() {
      return _hres;
    }

    public boolean isAppCommitted() {
      return _resp.isAppCommitted();
    }

    public boolean isError() {
      return _resp.isError();
    }

    public boolean isSuspended() {
      return _resp.isSuspended();
    }

    public void setAppCommitted(boolean appCommitted) {
      _resp.setAppCommitted(appCommitted);
    }

    public void setError() {
      _resp.setError();
    }

    public void setSuspended(boolean suspended) {
      _resp.setSuspended(suspended);
    }

    public javax.servlet.http.Cookie[] getCookies() {
      return _resp.getCookies();
    }

  }

  private class NoErrorResponse extends HttpServletResponseWrapper {
    boolean             _error = false;
    public NoErrorResponse(HttpServletResponse resp) {
      super(resp);
    }
    
    public void sendError(int sc) {
    }
    
    public void sendError(int sc, String msg) {
    }
  }
  /*
  private class DummyValveContext implements ValveContext {
    int _invoked = 0;

    public String getInfo() { 
      return "Dummy Valve Context"; 
    }
    public void invokeNext(Request request, Response response) {
      _invoked++;
    }
    public void resetInvokeCount() {
      _invoked = 0;
    }

    public int getInvokeCount() {
      return _invoked;
    }
  }
  */
}
