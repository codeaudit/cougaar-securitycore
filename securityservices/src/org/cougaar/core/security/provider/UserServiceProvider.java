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


package org.cougaar.core.security.provider;

import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.acl.user.AgentUserService;
import org.cougaar.core.security.acl.user.LdapUserServiceImpl;
import org.cougaar.core.security.services.acl.UserService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class UserServiceProvider
  extends BaseSecurityServiceProvider
{
  protected static final boolean AGENT_SERVICE = !Boolean.getBoolean("org.cougaar.core.security.provider.UserService.ldap");
  private UserService       _service;

  public UserServiceProvider(ServiceBroker sb, String community) {
    super(sb, community);
    if (sb == null) {
      throw new IllegalArgumentException("ServiceBroker should not be null");
    }
    if(AGENT_SERVICE){
      _service=new AgentUserService(sb, null);
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
  
  /* (non-Javadoc)
   * @see org.cougaar.core.security.provider.BaseSecurityServiceProvider#getInternalService(org.cougaar.core.component.ServiceBroker, java.lang.Object, java.lang.Class)
   */
  protected Service getInternalService(ServiceBroker sb, Object requestor, Class serviceClass) {
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
      _service = new AgentUserService(serviceBroker, null);
    }
    else {
      if(log.isDebugEnabled()){
        log.debug(" LdapUserServiceImpl  instance created with  "+ sb.toString());
      }
      _service = new LdapUserServiceImpl(serviceBroker);
    }
  }
  else {
    if(log.isDebugEnabled()){
      log.debug("Providing with User service that is already created :"+ _service.toString());
    }
  }
  return _service;
  }

  /* (non-Javadoc)
   * @see org.cougaar.core.security.provider.BaseSecurityServiceProvider#releaseInternalService(org.cougaar.core.component.ServiceBroker, java.lang.Object, java.lang.Class, java.lang.Object)
   */
  protected void releaseInternalService(ServiceBroker sb, Object requestor, Class serviceClass, Object service) {
  }
  
}
