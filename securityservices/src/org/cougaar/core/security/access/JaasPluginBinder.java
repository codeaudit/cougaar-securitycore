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

// Cougaar core services
import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.BinderWrapper;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.JaasClient;
import org.cougaar.core.security.services.auth.AuthorizationService;
import org.cougaar.core.security.services.auth.SecurityContextService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

/**
 * add following line to the .ini file to activate this binder:
 * Node.AgentManager.Agent.PluginManager.Binder = org.cougaar.core.security.access.JaasPluginBinderFactory
 *
 */
public class JaasPluginBinder
  extends BinderWrapper
{
  private Logger _log;
  private ExecutionContext _ec;
  private SecurityContextService _scs;
  private MessageAddress _agent;
 
  /** Creates new JaasPluginBinder */
  public JaasPluginBinder(BinderFactory bf, Object child) {
    super(bf,child);
  }

  public String toString() {
    return "JaasPluginBinder for " + getContainer();
  }

  private String getPluginName(){
    return getComponentDescription().getClassname();
  }

  private void doLoad() {
    super.load();
  }
  
  private void doStart() { 
    super.start();
  }
  
  public void load() {
    ServiceBroker sb = getServiceBroker();
    _log = (LoggingService)
      sb.getService(this, LoggingService.class, null);
    if(_log == null) {
      _log = LoggerFactory.getInstance().createLogger(this); 
    }
    _scs = (SecurityContextService)
      sb.getService(this, SecurityContextService.class, null);
    AgentIdentificationService ais = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null);
    _agent = ais.getMessageAddress();
    AuthorizationService as = (AuthorizationService)
	    sb.getService(this, AuthorizationService.class, null);
    // the getComponentDescription is exposed in cougaar 10.x
    _ec = as.createExecutionContext(_agent, getComponentDescription());
    _scs.setExecutionContext(_ec);
    JaasClient jc = new JaasClient(_ec);
    jc.doAs(getPluginName(),
            new java.security.PrivilegedAction() {
                public Object run() {
                  _log.debug("Plugin manager is loading: "
			    + getPluginName()
			    + " security context is : " + _ec);
                  doLoad();
                  return null;
                }
              }, false);
     _scs.resetExecutionContext();
     sb.releaseService(this, AgentIdentificationService.class, ais);
     sb.releaseService(this, AuthorizationService.class, as);
  }

   
  public void start() {
    _scs.setExecutionContext(_ec);
    JaasClient jc = new JaasClient(_ec);
    jc.doAs(getPluginName(),
            new java.security.PrivilegedAction() {
                public Object run() {
                  _log.debug("Plugin manager is starting: "
			    + getPluginName()
			    + " security context is : " + _ec);
                  doStart();
                  return null;
                }
              }, false);
    _scs.resetExecutionContext();
    ServiceBroker sb = getServiceBroker();
    sb.releaseService(this, SecurityContextService.class, _scs);
    if(_log instanceof LoggingService) {
      sb.releaseService(this, LoggingService.class, _log); 
    }
  }
}
