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
package org.cougaar.core.security.pedigree;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.List;
import java.util.Set;

import org.cougaar.core.blackboard.Blackboard;
import org.cougaar.core.blackboard.DirectiveMessage;
import org.cougaar.core.blackboard.EnvelopeTuple;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.domain.Factory;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.DomainForBlackboardService;


/**
 * @author srosset
 *
 * A proxy to the DomainForBlackboardService.
 * The DomainForBlackboardService is used by the Blackboard class to invoke
 * all logic providers upon receiving messages from the Distributor.
 */
class DomainForBlackboardServiceProxy implements DomainForBlackboardService {
  
  private DomainForBlackboardService    service;
  private ServiceBroker                 serviceBroker;
  private MessagePedigreeHandler        _pedigreeHandler;
  
  public DomainForBlackboardServiceProxy(DomainForBlackboardService svc,
      ServiceBroker sb) {
    service = svc;
    serviceBroker = sb;
    _pedigreeHandler = (MessagePedigreeHandler)
    AccessController.doPrivileged(new PrivilegedAction() {
      public Object run() {
        return MessagePedigreeHandler.getInstance();
      }
    });
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.service.DomainForBlackboardService#setBlackboard(org.cougaar.core.blackboard.Blackboard)
   */
  public void setBlackboard(Blackboard blackboard) {
    service.setBlackboard(blackboard);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.service.DomainForBlackboardService#invokeDelayedLPActions()
   */
  public void invokeDelayedLPActions() {
    service.invokeDelayedLPActions();
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.service.DomainForBlackboardService#invokeEnvelopeLogicProviders(org.cougaar.core.blackboard.EnvelopeTuple, boolean)
   */
  public void invokeEnvelopeLogicProviders(EnvelopeTuple tuple,
      boolean persistenceEnv) {
    service.invokeEnvelopeLogicProviders(tuple, persistenceEnv);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.service.DomainForBlackboardService#invokeMessageLogicProviders(org.cougaar.core.blackboard.DirectiveMessage)
   */
  public void invokeMessageLogicProviders(DirectiveMessage message) {
    /* Add the pedigree to a ThreadLocal variable so that the RootPlanProxy
     * can retrieve it when it is invoked.
     * The stack frames would look like this:
     * 
     * RootPlanProxy.add
     * LogicProviderXYZ.execute
     * DomainManager.invokeMessageLogicProviders
     * DomainForBlackboardServiceProxy.invokeMessageLogicProviders
     * Blackboard.applyMessageAgainstLogicProviders
     * Distributor.receiveMessages
     * StandardBlackboard$BlackboardForAgentImpl.receiveMessages
     * QueueHandler.receiveMessages
     */
    _pedigreeHandler.setThreadLocalPedigree(message);
    
    // Now invoke the logic providers.
    service.invokeMessageLogicProviders(message);
    
    /* Now remove the pedigree from the ThreadLocal variable.
     */
    _pedigreeHandler.resetThreadLocalPedigree();
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.service.DomainForBlackboardService#invokeRestartLogicProviders(org.cougaar.core.mts.MessageAddress)
   */
  public void invokeRestartLogicProviders(MessageAddress cid) {
    service.invokeRestartLogicProviders(cid);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.service.DomainForBlackboardService#invokeABAChangeLogicProviders(java.util.Set)
   */
  public void invokeABAChangeLogicProviders(Set communities) {
    service.invokeABAChangeLogicProviders(communities);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.service.DomainService#getFactory(java.lang.String)
   */
  public Factory getFactory(String domainName) {
    return service.getFactory(domainName);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.service.DomainService#getFactory(java.lang.Class)
   */
  public Factory getFactory(Class domainClass) {
    return service.getFactory(domainClass);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.service.DomainService#getFactories()
   */
  public List getFactories() {
    return service.getFactories();
  }
  
}
