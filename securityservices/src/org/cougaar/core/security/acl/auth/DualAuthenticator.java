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

import java.io.IOException;
import java.util.ResourceBundle;
import java.util.MissingResourceException;

import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.catalina.Request;
import org.apache.catalina.Response;
import org.apache.catalina.Context;
import org.apache.catalina.Container;
import org.apache.catalina.ValveContext;
import org.apache.catalina.HttpRequest;
import org.apache.catalina.HttpResponse;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.authenticator.SSLAuthenticator;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.connector.HttpResponseWrapper;

import java.security.Principal;

public class DualAuthenticator extends ValveBase {
  private static ResourceBundle _authenticators = null;
  AuthenticatorBase _primaryAuth;
  AuthenticatorBase _secondaryAuth;
  LoginConfig       _loginConfig = new LoginConfig();
  Context           _context     = null;

  public DualAuthenticator() {
    this(new SSLAuthenticator(), new BasicAuthenticator());
  }

  public DualAuthenticator(AuthenticatorBase secondaryAuth) {
    this(new SSLAuthenticator(), secondaryAuth);
  }

  public DualAuthenticator(AuthenticatorBase primaryAuth,
                           AuthenticatorBase secondaryAuth) {
    setPrimaryAuthenticator(primaryAuth);
    setSecondaryAuthenticator(secondaryAuth);
  }

  /**
   * Valve callback. First check the primary authentication method
   * and if not authenticated, call the secondary authentication method.
   */
  public void invoke(Request request, Response response,
                     ValveContext context) throws IOException, ServletException {
    setContainer();
     HttpServletResponse no_err =
       new NoErrorResponse((HttpServletResponse) response.getResponse());
     ResponseDummy tmpRes = new ResponseDummy((HttpResponse) response, no_err);

     _primaryAuth.invoke(request,tmpRes,context);
    HttpServletRequest hreq = (HttpServletRequest) request.getRequest();
    Principal principal = hreq.getUserPrincipal();
    if (principal == null) {
//       System.out.println("Trying secondary authentication....");
      _secondaryAuth.invoke(request,response,context);
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
//     _primaryAuth.setDebug(100);
  }

  public void setSecondaryAuthenticator(AuthenticatorBase secondaryAuth) {
    _secondaryAuth = secondaryAuth;
//     _secondaryAuth.setDebug(100);
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
}
