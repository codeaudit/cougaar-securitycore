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
package org.cougaar.core.security.coreservices.tomcat;

import java.lang.reflect.Method;
import java.io.IOException;
import javax.servlet.ServletException;

import org.apache.catalina.Valve;
import org.apache.catalina.valves.ValveBase;
import org.apache.catalina.Contained;
import org.apache.catalina.Container;
import org.apache.catalina.ValveContext;
import org.apache.catalina.Request;
import org.apache.catalina.Response;

/**
 * A Valve for Tomcat 4.0 that will use
 * org.cougaar.core.security.acl.auth.DualAuthenticator if it
 * exists and the System property
 * <code>org.cougaar.core.security.coreservices.tomcat.enableAuth</code> 
 * is "true".
 * <p>
 * The <code>server.xml</code> should have within the &lt;Context&gt; section:
 * <pre>
 *   &lt;Valve className="org.cougaar.core.security.coreservices.tomcat.AuthValve" realmName="Cougaar" authMethod="DIGEST"/&gt;
 * </pre>
 * <p>
 * Where realmName is the realm to use for authenticating users and
 * authMethod is the secondary method for authentication. It accepts any of the
 * standard methods available for authentication in servlet 2.3 spec.
 * Remember that the primary authentication is always CERT, so don't use that.
 *
 * @author George Mount <gmount@nai.com>
 */
public class AuthValve implements Valve, Contained {

  private static final String PROP_ENABLE = "org.cougaar.core.security.coreservices.tomcat.enableAuth";
  private String _authClass  = "org.cougaar.core.security.acl.auth.DualAuthenticator";
  private ValveBase _authValve = null;
  private Container _container = null;

  /** 
   * Default constructor.
   */
  public AuthValve() {
    init();
  }

  /**
   * returns the DualAuthenticator Valve if it is available.
   */
  public ValveBase getValve() {
    return _authValve;
  }

  private synchronized void init() {
    if (Boolean.getBoolean(PROP_ENABLE)) {
      try {
        Class c = Class.forName(_authClass);
        _authValve = (ValveBase) c.newInstance();
      } catch (ClassNotFoundException e) {
        System.out.println("Error: could not find class " + _authClass);
      } catch (ClassCastException e) {
        System.out.println("Error: the class " + _authClass + " is not a Valve");
      } catch (Exception e) {
        System.out.println("Error: could not load the class " + _authClass);
      }
    }
  }

  /**
   * returns the DualAuthenticator getInfo() if available or "AuthValve"
   * otherwise
   */
  public String getInfo() {
    if (_authValve != null) {
      return _authValve.getInfo();
    }
    return "AuthValve";
  }

  /**
   * Calls DualAuthenticator invoke() if available or calls
   * context.invokeNext() if not.
   */
  public void invoke(Request request, Response response, ValveContext context) 
    throws IOException, ServletException {
    if (_authValve != null) {
      _authValve.invoke(request, response, context);
    } else {
      context.invokeNext(request, response);
    }
  }

  /**
   * Sets the Valve class to use.
   */
  public void setValveClass(String authClass) {
    _authClass = authClass;
    init();
  }
  
  /**
   * Returns the Valve class that was last set.
   */
  public String getValveClass() {
    return _authClass;
  }

  /**
   * Calls DualAuthenticator setRealmName() if available
   */
  public void setRealmName(String realmName) {
    if (_authValve != null) {
      try {
        Method m = _authValve.getClass().
          getMethod("setRealmName", new Class[] { String.class });
        m.invoke( _authValve, new Object[] { realmName } );
      } catch (Exception e) {
        e.printStackTrace();
      }
    } 
  }

  /**
   * Returns DualAuthenticator getRealmName() if available or
   * <code>null</code> otherwise.
   */
  public String getRealmName() {
    if (_authValve != null) {
      try {
        Method m = _authValve.getClass().getMethod("getRealmName", null);
        return (String) m.invoke( _authValve, null );
      } catch (Exception e) {
        // don't worry about it.
      }
    } 
    return null;
  }

  /**
   * Calls DualAuthenticator setAuthMethod() if available
   */
  public void setAuthMethod(String authMethod) {
    if (_authValve != null) {
      try {
        Method m = _authValve.getClass().
          getMethod("setAuthMethod", new Class[] { String.class });
        m.invoke( _authValve, new Object[] { authMethod } );
      } catch (Exception e) {
        // don't worry about it.
      }
    } 
  }

  /**
   * Returns DualAuthenticator getAuthMethod() if available or
   * <code>null</code> otherwise.
   */
  public String getAuthMethod() {
    if (_authValve != null) {
      try {
        Method m = _authValve.getClass().getMethod("getAuthMethod", null);
        return (String) m.invoke( _authValve, null );
      } catch (Exception e) {
        // don't worry about it.
      }
    } 
    return null;
  }

  /**
   * Sets the context container
   */
  public void setContainer(Container container) {
    if (_authValve != null) {
      _authValve.setContainer(container);
    } 
    _container = container;
  }

  /**
   * Returns the context container
   */
  public Container getContainer() {
    if (_authValve != null) {
      return _authValve.getContainer();
    }
    return _container;
  }
}
