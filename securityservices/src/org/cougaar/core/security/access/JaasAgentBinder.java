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
import org.cougaar.core.security.auth.JaasClient;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import java.util.List;

/*
 * add following line to the Node.ini file to activate this binder:
 * Node.AgentManager.Binder = org.cougaar.core.security.access.JaasAgentBinderFactory
 *
 */

public class JaasAgentBinder
  extends BinderWrapper
{
  //private ServiceBroker _serviceBroker;
  private Logger _log;
  private MessageAddress _agent;

  /** Creates new JassAgentBinder */
  public JaasAgentBinder(BinderFactory bf, Object child) {
    super(bf,child);
  }
  private void setLoggingService(LoggingService log) {
    _log = log;
    if(_log == null) {
      _log = LoggerFactory.getInstance().createLogger(this);
      if (_log == null) {
	throw new RuntimeException("Unable to get LoggingService");
      }
    }
  }
  public String toString() {
    return "JaasAgentBinder for "+getContainer();
  }
  // get the name of the Agent
  private String getAgentName(){
    return ((_agent == null) ? "" : _agent.toString());
  }
  private MessageAddress getAgentIdentifier() {
    Object o = getComponentDescription().getParameter();
  
    MessageAddress cid = null;
    if (o instanceof MessageAddress) {
      cid = (MessageAddress) o;
    } else if (o instanceof String) {
      cid = MessageAddress.getMessageAddress((String) o);
    } else if (o instanceof List) {
      List l = (List)o;
      if (l.size() > 0) {
        Object o1 = l.get(0);
        if (o1 instanceof MessageAddress) {
          cid = (MessageAddress) o1;
        } else if (o1 instanceof String) {
          cid = MessageAddress.getMessageAddress((String) o1);
        }
      }
    }

    return cid; 
  }
  private void doLoad() { 
    super.load();
  }
  
  private void doStart() { 
    super.start();
  } 

  public void load() {
    ServiceBroker sb = getServiceBroker();
    setLoggingService((LoggingService)
      sb.getService(this, LoggingService.class, null));
    AgentIdentificationService ais = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null);
    if(ais == null) {
      _agent = getAgentIdentifier();
    }
    else {
      _agent = ais.getMessageAddress(); 
      sb.releaseService(this, AgentIdentificationService.class, ais);
    }
    JaasClient jc = new JaasClient();
    jc.doAs(getAgentName(),
            new java.security.PrivilegedAction() {
                public Object run() {
		  if (_log.isDebugEnabled()) {
		    _log.debug("Agent manager is loading: "
			       + getAgentName());
		  }
                  JaasClient.printPrincipals();
                  doLoad();
                  return null;
                }
              }, true);
  }

   
  public void start() {
    JaasClient jc = new JaasClient();
    jc.doAs(getAgentName(),
            new java.security.PrivilegedAction() {
                public Object run() {
		  if (_log.isDebugEnabled()) {
		    _log.debug("Agent manager is starting: "
			       + getAgentName());
		  }
                  doStart();
                  return null;
                }
              }, false);
    if(_log instanceof LoggingService) {
      getServiceBroker().releaseService(this, LoggingService.class, _log);
    }
  }
}
