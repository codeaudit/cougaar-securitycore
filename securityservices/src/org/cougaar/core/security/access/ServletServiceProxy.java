/**
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
 */

package org.cougaar.core.security.access;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.ServletService;
import org.cougaar.core.service.AgentIdentificationService;

import org.cougaar.core.security.acl.auth.URIPrincipal;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.JaasClient;

import java.io.IOException;
import java.security.PrivilegedAction;
import java.util.Hashtable;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

class ServletServiceProxy extends SecureServiceProxy
  implements ServletService {
  
  private ServletService _ss;
  private Object _requestor;
  private String _agentName;
  
  // for servlet to SecureServlet mapping
  private static Hashtable _servletTable = new Hashtable();
  
  public ServletServiceProxy(ServletService ss, Object requestor, ServiceBroker sb) {
    super(sb);
    _ss = ss;
    _requestor = requestor;  
    // get the name of the agent
    AgentIdentificationService ais = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null);
    _agentName = ais.getName();
    sb.releaseService(this, AgentIdentificationService.class, ais);
  }
  public int getHttpPort() {
    return _ss.getHttpPort();
  }
  public int getHttpsPort() {
    return _ss.getHttpsPort();
  }
  public void register(String path, Servlet servlet) 
    throws Exception {
    _ss.register(path, addServlet(path, servlet));
  }
  public void unregister(String path) {
    removeServlet(path);
    _ss.unregister(path);
  }
  public void unregisterAll() {
    removeAll();
    _ss.unregisterAll();  
  }
  
  private Servlet addServlet(String path, Servlet servlet) {
    Servlet ss = new SecureServlet(servlet, path);
    _servletTable.put(path, ss); 
    return ss;
  }
  private Servlet removeServlet(String path) {
    return (Servlet)_servletTable.remove(path);
  }
  private void removeAll() {
    _servletTable.clear();
  }
   
  private class SecureServlet implements Servlet {
    private Servlet _servlet;
    private URIPrincipal _up;
    
    public SecureServlet(Servlet servlet, String path) {
      _servlet = servlet;
      // construct the uri for this servlet
      _up = new URIPrincipal("/$" + _agentName + path);
    }
    
    public void destroy() {
      // need to set the JAAS context since this is called by tomcat
      JaasClient jc = new JaasClient();
      jc.doAs(_up, 
              new java.security.PrivilegedAction() {
                public Object run() {
                  _servlet.destroy(); 
                  return null;
                } 
       });
    }
       
    public ServletConfig getServletConfig() {
      return _servlet.getServletConfig();
    }
    
    public String getServletInfo() {
      return _servlet.getServletInfo();
    }
    
    public void init(ServletConfig config) 
      throws ServletException {
      // need to set the JAAS context since this is called by tomcat
      final ServletConfig fConfig = config;
      JaasClient jc = new JaasClient();
      Object o = jc.doAs(_up, 
                  new java.security.PrivilegedAction() {
                    public Object run() {
                    Object retObj = null;
                    try {
                      _servlet.init(fConfig);
                    }
                    catch(ServletException se) {
                      retObj = se;
                    }
                    return retObj;
                  }
                });
      // throw exception if one was returned from the privileged action
      if(o != null && o instanceof Exception) {
        if(o instanceof ServletException) {
          throw (ServletException)o;
        }
        else {
          throw new RuntimeException("Unhandled exception: " + o,
				     (Exception) o); 
        }
      }
    }
    
    public void service(ServletRequest req, ServletResponse res) 
      throws ServletException, IOException {
      final ServletRequest fReq = req;
      final ServletResponse fRes = res;
      // add to jaas context
      JaasClient jc = new JaasClient();
      Object o = jc.doAs(_up,
                  new java.security.PrivilegedAction() {
                    public Object run() {
                    Object retObj = null;
                    try {
                      _servlet.service(fReq, fRes);
                    }
                    catch(Exception e) {
                      retObj = e;
                    }
                    return retObj;
                  }
                });
      // throw exception if one was returned from the privileged action
      if(o != null && o instanceof Exception) {
        if(o instanceof ServletException) {
          throw (ServletException)o;
        }
        else if(o instanceof IOException) {
          throw (IOException)o;
        }
        else {
          throw new RuntimeException("Unhandled exception: " + o,
                                     (Exception) o);
        }
      }
    } // end void service
  } // end class SecureServlet
} // end class ServletServiceProxy
