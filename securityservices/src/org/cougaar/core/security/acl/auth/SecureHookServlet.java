/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
 
 
 
 
 
 


package org.cougaar.core.security.acl.auth;

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

import org.cougaar.util.log.LoggerFactory;

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
    if (_log.isDebugEnabled()) {
      String s = "service - principal:" + principal;
      if (req != null && req instanceof HttpServletRequest) {
	s = s + " - req: " + ((HttpServletRequest)req).getRequestURI();
      }
      _log.debug(s);
    }

    // This audit is commented out for now because I am moving the audit
    // to DualAuthenticator.  -Timothy
    /*
     *if (req instanceof HttpServletRequest) {
     *  HttpServletRequest hreq = (HttpServletRequest) req;
     *  subject.getPrincipals().add(new URIPrincipal(hreq.getRequestURI()));
     * 
     *    //log access to Resource
     *   AuditLogger.logWebEvent((HttpServletRequest)req,
     *			      getServletName(hreq), getAgentName(hreq));
     *
     *}
     */
     
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

  /*
   * getAgentName and getServletName used to live here - Timothy
   */

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
