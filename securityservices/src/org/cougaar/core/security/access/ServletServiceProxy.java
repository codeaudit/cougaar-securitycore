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
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.ServletService;
import org.cougaar.core.service.AgentIdentificationService;

import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.services.auth.AuthorizationService;

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
  private AuthorizationService _as;
  private Object _requestor;
  private MessageAddress _agent;
  
  // for servlet to SecureServlet mapping
  private static Hashtable _servletTable = new Hashtable();
  
  public ServletServiceProxy(ServletService ss, Object requestor, ServiceBroker sb) {
    super(sb);
    _ss = ss;
    _as = (AuthorizationService)
      sb.getService(this, AuthorizationService.class, null);
    _requestor = requestor;  
    // get the name of the agent
    AgentIdentificationService ais = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null);
    _agent = ais.getMessageAddress();
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
    private ExecutionContext _ec;
    
    public SecureServlet(Servlet servlet, String path) {
      _servlet = servlet;
      // construct the uri for this servlet
      String uri = "/$" + _agent + path;
      _ec = _as.createExecutionContext(_agent, uri, null);
    }
    
    public void destroy() {
      _scs.setExecutionContext(_ec);
      _servlet.destroy(); 
      _scs.resetExecutionContext();
    }
       
    public ServletConfig getServletConfig() {
      return _servlet.getServletConfig();
    }
    
    public String getServletInfo() {
      return _servlet.getServletInfo();
    }
    
    public void init(ServletConfig config) 
      throws ServletException {
      try {
        _scs.setExecutionContext(_ec);
        _servlet.init(config);
      }
      catch(ServletException se) {
        throw se;
      }
      finally {
        _scs.resetExecutionContext();
      }
    }
    
    public void service(ServletRequest req, ServletResponse res) 
      throws ServletException, IOException {
      try {
        _scs.setExecutionContext(_ec);
        _servlet.service(req, res);
      }
      catch(ServletException se) {
        throw se;
      }
      catch(IOException ioe) {
        throw ioe; 
      }
      finally {
        _scs.resetExecutionContext();
      }
    } // end void service
  } // end class SecureServlet
} // end class ServletServiceProxy
