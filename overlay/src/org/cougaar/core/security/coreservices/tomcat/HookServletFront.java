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

package org.cougaar.core.security.coreservices.tomcat;

import java.io.IOException;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.cougaar.lib.web.tomcat.HookServlet;

/**
 * This class is designed to load 
 * org.cougaar.core.security.acl.auth.SecureHookServlet if it
 * exists and the System property
 * <code>org.cougaar.core.security.coreservices.tomcat.enableAuth</code> 
 * is "true".
 * <p>
 * The <code>web.xml</code> should have within the &lt;web-app&gt; element:
 * <pre>
 *   &lt;servlet&gt;
 *       &lt;servlet-name&gt;cougaar&lt;/servlet-name&gt;
 *       &lt;servlet-class&gt;org.cougaar.core.security.coreservices.tomcat.HookServletFront&lt;/servlet-class&gt;
 *   &lt;/servlet&gt;
 * </pre>
 * <p>
 * a privileged action under the principal of the user
 * who has logged in.
 */
public class HookServletFront implements Servlet {
  private static final String PROP_ENABLE = "org.cougaar.core.security.coreservices.tomcat.enableAuth";

  private String  _servletClass = "org.cougaar.core.security.acl.auth.SecureHookServlet";
  private String  _fallbackClass = "org.cougaar.lib.web.tomcat.HookServlet;";

  private Servlet _hookServlet = null;
  
  /**
   * default constructor
   */
  public HookServletFront() {
    if (Boolean.getBoolean(PROP_ENABLE)) {
      try {
        Class c = Class.forName(_servletClass);
        _hookServlet = (Servlet) c.newInstance();
      } catch (ClassNotFoundException e) {
        System.out.println("Error: could not find class " + _servletClass);
      } catch (ClassCastException e) {
        System.out.println("Error: the class " + _servletClass + " is not a Servlet");
      } catch (Exception e) {
        System.out.println("Error: Could not load the class " + _servletClass);
      }
    }
    if (_hookServlet == null) {
      _hookServlet = new HookServlet();
    }
  }

  /**
   * Call the hook servlet service
   */
  public void service(ServletRequest req, ServletResponse res) 
    throws ServletException, IOException {
    _hookServlet.service(req,res);
  }

  /**
   * Prepare the hook servlet to be destroyed.
   */
  public void destroy() {
    _hookServlet.destroy();
  }

  /**
   * Calls the Hook Servlet init()
   */
  public void init(ServletConfig config) throws ServletException {
    _hookServlet.init(config);
  }

  /**
   * Return the ServletConfig we got in init()
   */
  public ServletConfig getServletConfig() {
    return _hookServlet.getServletConfig();
  }

  /**
   * Returns the hook servlet's info, if available
   */
  public String getServletInfo() {
    return _hookServlet.getServletInfo();
  }
}
