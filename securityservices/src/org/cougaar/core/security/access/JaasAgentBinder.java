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
 * Created on March 18, 2002, 2:42 PM
 */

package org.cougaar.core.security.access;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.core.component.BinderWrapper;
import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.ComponentDescription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import org.cougaar.core.security.auth.JaasClient;

import java.util.List;
import java.util.Iterator;

/*
 * add following line to the Node.ini file to activate this binder:
 * Node.AgentManager.Binder = org.cougaar.core.security.access.JaasAgentBinderFactory
 *
 */

public class JaasAgentBinder
  extends BinderWrapper
{
  private ServiceBroker _serviceBroker;
  private Logger _log;
  private MessageAddress _agent;

  /** Creates new JassAgentBinder */
  public JaasAgentBinder(BinderFactory bf, Object child) {
    super(bf,child);
  }
  public void setLoggingService(LoggingService log) {
    _log = log;
    if(_log == null) {
      _log = LoggerFactory.getInstance().createLogger(this);
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
                  _log.debug("Agent manager is loading: "
			    + getAgentName());
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
                  _log.debug("Agent manager is starting: "
			    + getAgentName());
                  doStart();
                  return null;
                }
              }, false);
    if(_log instanceof LoggingService) {
      getServiceBroker().releaseService(this, LoggingService.class, _log);
    }
  }
}
