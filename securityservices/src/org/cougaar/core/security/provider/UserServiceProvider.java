/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */

package org.cougaar.core.security.provider;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceProvider;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.acl.user.AgentUserService;
import org.cougaar.core.security.acl.user.LdapUserServiceImpl;
import org.cougaar.core.security.services.acl.UserService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;

import java.util.Iterator;

public class UserServiceProvider implements ServiceProvider
{
  protected static final boolean AGENT_SERVICE = !Boolean.getBoolean("org.cougaar.core.security.provider.UserService.ldap");
  private UserService       _service;
  private MessageAddress    _agent=null;;
  private boolean           _listenerAdded =false;
  private static Logger     _log=LoggerFactory.getInstance().createLogger(UserServiceProvider.class);
  private ServiceBroker     _nodeAgentsb=null;
  private ServiceBroker     _rootsb=null;

  public UserServiceProvider(MessageAddress agent) {
    _agent = agent;
  }

  public UserServiceProvider(ServiceBroker sb ) {
    _nodeAgentsb=sb;
    if(AGENT_SERVICE){
      _service=new AgentUserService(sb);
    }
    else{
      _service = new LdapUserServiceImpl(sb);
    }
  
    
  }
  public static void  setRootServiceBroker(ServiceBroker sb){
    if (!AGENT_SERVICE) {
      LdapUserServiceImpl.setRootServiceBroker(sb);
    }
   
  }
  
  /**
   * Get a service.
   * @param sb a Service Broker
   * @param requestor the requestor of the service
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @return a service
   */
  public synchronized Object getService(ServiceBroker sb,
                                        Object requestor,
                                        Class serviceClass) {
    /*
      if (_service == null) {
      _log.debug("requestor for User service is :"+requestor.toString());
      _log.debug("service broker is "+ sb.toString());
      Iterator iter = sb.getCurrentServiceClasses();
      _log.debug("Current services that can be obtained at UserServiceProvider  are:"); 
      Object object=null;
      while(iter.hasNext()){
      object =iter.next();
      _log.debug("Service ----->"+ object.toString());
      }
      if (_agent == null) {
      _log.debug(" Agent is null in UserServiceProvider ");
      AgentIdentificationService ais = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null);
      if((ais==null) &&(!_listenerAdded)) {
      _log.debug("Adding AgentIdentificationService listener");
      ServiceAvailableListener listener = new AgentIdentityServiceListener(); 
      sb.addServiceListener(listener);
      _listenerAdded=true;
      return null;
      }
      if((ais!=null)&&(_agent==null)) {
      _agent = ais.getMessageAddress();
      }
      }
      if (AGENT_SERVICE) {
      _service = new AgentUserService(sb, _agent);
      _log.debug(" USER SERVICE instance created with  "+ sb.toString());
      _log.debug(" USER SERVICE instance created"+_service.toString());
      } else {
      _log.debug(" LdapUserServiceImpl  instance created with  "+ sb.toString());
      _service = new LdapUserServiceImpl(sb, _agent);
      }
      }
    */

    if (_service == null) {
      if (AGENT_SERVICE) {
        _service = new AgentUserService(_nodeAgentsb);
      }
      else {
        if(_log.isDebugEnabled()){
          _log.debug(" LdapUserServiceImpl  instance created with  "+ sb.toString());
        }
        _service = new LdapUserServiceImpl(_nodeAgentsb);
      }
    }
    else {
      if(_log.isDebugEnabled()){
        _log.debug("Providing with User service that is already created :"+ _service.toString());
      }
    }
    return _service;
  }

  /** Release a service.
   * @param sb a Service Broker.
   * @param requestor the requestor of the service.
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @param service the service to be released.
   */
  public synchronized void releaseService(ServiceBroker sb,
                                          Object requestor,
                                          Class serviceClass,
                                          Object service) {
  }
  
}
