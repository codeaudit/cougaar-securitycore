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

package org.cougaar.core.security.access;

import java.io.IOException;
import java.util.Hashtable;
import java.security.PrivilegedAction;
import java.security.AccessController;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.services.auth.AuthorizationService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.ServletService;

class ServletServiceProxy extends SecureServiceProxy
  implements ServletService {
  
  private ServletService _ss;
  private AuthorizationService _as;
  //private Object _requestor;
  private MessageAddress _agent;
  
  // for servlet to SecureServlet mapping
  private static Hashtable _servletTable = new Hashtable();
  
  public ServletServiceProxy(ServletService ss, Object requestor, final ServiceBroker sb) {
    super(sb);
    _ss = ss;
    AccessController.doPrivileged(new PrivilegedAction() {
      public Object run() {
        _as = (AuthorizationService)
            sb.getService(this, AuthorizationService.class, null);
        return null;
      }
    });
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
