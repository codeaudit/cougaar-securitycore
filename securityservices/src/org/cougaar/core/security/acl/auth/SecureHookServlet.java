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

import org.cougaar.core.security.audit.AuditLogger;
import org.cougaar.util.log.LoggerFactory;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedAction;

import javax.security.auth.Subject;
import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * This class is designed to run the entire servlet service() as
 * a privileged action under the principal of the user
 * who has logged in.
 */
public class SecureHookServlet implements Servlet {
  /**
   * The hook servlet to take all the calls
   */
  private Servlet _hookServlet = null;
  private org.cougaar.util.log.Logger _log;

  /**
   * default constructor
   */
  public SecureHookServlet() {
    _log = LoggerFactory.getInstance().createLogger(SecureHookServlet.class);
  }

  /**
   * Call the hook servlet using the user Principal.
   */
  public void service(ServletRequest req, ServletResponse res) 
    throws ServletException, IOException {
    Principal principal = null;
    if (req instanceof HttpServletRequest) {
      principal = ((HttpServletRequest) req).getUserPrincipal();
    }
    Subject subject = new Subject();
    if (principal != null) {
      subject.getPrincipals().add(principal);
    }
    if (req instanceof HttpServletRequest) {
      HttpServletRequest hreq = (HttpServletRequest) req;
      subject.getPrincipals().add(new URIPrincipal(hreq.getRequestURI()));

      //log access to Resource
      AuditLogger.logWebEvent((HttpServletRequest)req,
			      getServletName(hreq), getAgentName(hreq));
    }
    Exception e = (Exception) Subject.doAs(subject,new ServletCall(req,res));
   
    if (e != null) {
      if (e instanceof RuntimeException) {
        throw (RuntimeException) e;
      } else if (e instanceof IOException) {
        throw (IOException) e;
      } else if (e instanceof ServletException) {
        throw (ServletException) e;
      }
    }
  }

  /**
   * Prepare the hook servlet to be destroyed.
   */
  public void destroy() {
    if (_hookServlet != null) _hookServlet.destroy();
  }

  /**
   * Get the agent name from the servlet request
   * A Cougaar URL looks like this:
   *   http://<hostname>:<port_number>/$<agent_name>/<servlet_name>
   */
  private String getAgentName(HttpServletRequest hreq) {
    if (hreq == null) {
      return null;
    }
    String urlString = hreq.getRequestURI();
    if (urlString == null || urlString.length() == 0) {
      return null;
    }
    if (urlString.charAt(0) != '/') {
      _log.warn("Error parsing URL. Unexpected character: " + urlString);
      return null;
    }
    urlString = urlString.substring(1, urlString.length());
    int last = urlString.indexOf('/');
    if (last == -1) {
      last = urlString.length();
    }
    urlString = urlString.substring(0, last);
    int first = urlString.indexOf('$');
    if (first == -1) {
      return null;
    }
    return urlString.substring(first+1, last);
  }

  /**
   * Get the servlet name from the servlet request
   * A Cougaar URL looks like this:
   *   http://<hostname>:<port_number>/$<agent_name>/<servlet_name>
   */
  private String getServletName(HttpServletRequest hreq) {
    if (hreq == null) {
      return null;
    }
    String urlString = hreq.getRequestURI();
    if (urlString == null || urlString.length() == 0) {
      return null;
    }
    if (urlString.charAt(0) != '/') {
      _log.warn("Error parsing URL. Unexpected character: " + urlString);
      return null;
    }
    if (urlString.length() == 1) {
      return urlString;
    }
    else if (urlString.charAt(1) == '$') {
      int first = urlString.indexOf('/', 1);
      if (first == -1) {
	return null;
      }
      else {
	return urlString.substring(first, urlString.length());
      }
    }
    else {
      return urlString.substring(1, urlString.length());
    }
  }

  /**
   * Initializes the servlet and hook servlet. Takes the "servletClass"
   * parameter as the class name of the hook servlet to use.
   */
  public void init(ServletConfig config) throws ServletException {
    String servletName = config.getInitParameter("servletClass");
    if (servletName == null) {
      servletName = "org.cougaar.lib.web.tomcat.HookServlet";
    }
    try {
      Class hsc = Class.forName(servletName);
      _hookServlet = (Servlet) hsc.newInstance();
      _hookServlet.init(config);
    } catch (Exception e) {
      //System.out.println("Couldn't start the hook servlet: " + servletName);
      e.printStackTrace();
    }
  }

  /**
   * Return the ServletConfig we got in init()
   */
  public ServletConfig getServletConfig() {
    if (_hookServlet == null) return null;
    return _hookServlet.getServletConfig();
  }

  /**
   * Returns the hook servlet's info, if available
   */
  public String getServletInfo() {
    if (_hookServlet == null) return "Uninitialized Secure Hook Servlet";
    else return _hookServlet.getServletInfo();
  }

  private class ServletCall implements PrivilegedAction {
    ServletRequest  _req;
    ServletResponse _res;

    public ServletCall(ServletRequest req, ServletResponse res) {
      _req = req;
      _res = res;
    }
    
    public Object run() {
      try {
        if (_hookServlet != null) {
          _hookServlet.service(_req, _res);
        }
        return null;
      } catch (Exception e) {
        return e;
      }
    }
  }
}
