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
  
  // for servlet to SecureServlet mapping
  private static Hashtable _servletTable = new Hashtable();
  
  public ServletServiceProxy(ServletService ss, Object requestor, ServiceBroker sb) {
    super(sb);
    _ss = ss;
    _requestor = requestor;  
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
    Servlet ss = new SecureServlet(servlet, _scs.getExecutionContext());
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
    
    public SecureServlet(Servlet servlet, ExecutionContext ec) {
      _servlet = servlet;
      _ec = ec;
    }
    
    public void destroy() {
      _servlet.destroy(); 
    }
       
    public ServletConfig getServletConfig() {
      return _servlet.getServletConfig();
    }
    
    public String getServletInfo() {
      return _servlet.getServletInfo();
    }
    
    public void init(ServletConfig config) 
      throws ServletException {
      _scs.setExecutionContext(_ec);
      _servlet.init(config);
      _scs.resetExecutionContext();
    }
    
    public void service(ServletRequest req, ServletResponse res) 
      throws ServletException, IOException {
      _scs.setExecutionContext(_ec);
      final ServletRequest fReq = req;
      final ServletResponse fRes = res;
      // add to jaas context
      JaasClient jc = new JaasClient();
      Object o = jc.doAs(_ec, 
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
                }, false);
      _scs.resetExecutionContext();
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
