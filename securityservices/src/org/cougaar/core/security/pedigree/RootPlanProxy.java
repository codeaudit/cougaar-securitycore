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
import java.util.Collection;
import java.util.Enumeration;

import org.cougaar.core.blackboard.ABATranslation;
import org.cougaar.core.blackboard.Blackboard;
import org.cougaar.core.blackboard.Directive;
import org.cougaar.core.blackboard.PublishHistory;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.domain.DelayedLPAction;
import org.cougaar.core.domain.RootPlan;
import org.cougaar.core.security.services.auth.Pedigree;
import org.cougaar.core.security.services.auth.PedigreeService;
import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;
import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


/**
 * @author srosset
 *
 * A proxy class that wraps the RootPlan service.
 * The RootPlan is used by LogicProviders to publish blackboard objects
 * upon receving messages from the MTS.
 */
public class RootPlanProxy 
implements RootPlan
{
  private RootPlan rootPlan;
  private MessagePedigreeHandler pedigreeHandler;
  private ServiceBroker serviceBroker;
  private PedigreeService pedigreeService;
  private static Logger _log;
  static {
    _log = LoggerFactory.getInstance().createLogger(RootPlanProxy.class);
  }
  
  public RootPlanProxy(RootPlan rootPlan, ServiceBroker broker) {
    this.rootPlan = rootPlan;
    this.serviceBroker = broker;
    if (_log.isDebugEnabled()) {
      _log.debug("Instantiating " + getClass().getName());
    }
    pedigreeHandler = (MessagePedigreeHandler)
    AccessController.doPrivileged(new PrivilegedAction() {
      public Object run() {
        return MessagePedigreeHandler.getInstance();
      }
    });
    pedigreeService = (PedigreeService)
    serviceBroker.getService(this, PedigreeService.class, null);
    if (pedigreeService == null) {
      if (_log.isErrorEnabled()) {
        _log.error("Unable to retrieve " + PedigreeService.class.getName());
      }
    }
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.domain.RootPlan#findUniqueObject(org.cougaar.core.util.UID)
   */
  public UniqueObject findUniqueObject(UID uid) {
    if (_log.isDebugEnabled()) {
      _log.debug("findUniqueObject:" + uid);
    }
    return rootPlan.findUniqueObject(uid);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.domain.RootPlan#delayLPAction(org.cougaar.core.domain.DelayedLPAction)
   */
  public void delayLPAction(DelayedLPAction dla) {
    if (_log.isDebugEnabled()) {
      _log.debug("delayLPAction");
    }
    rootPlan.delayLPAction(dla);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardServesDomain#searchBlackboard(org.cougaar.util.UnaryPredicate)
   */
  public Enumeration searchBlackboard(UnaryPredicate predicate) {
    if (_log.isDebugEnabled()) {
      _log.debug("searchBlackboard");
    }
    return rootPlan.searchBlackboard(predicate);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardServesDomain#add(java.lang.Object)
   */
  public void add(Object o) {
    setPedigree(o, PUBLISH_ADD);
    rootPlan.add(o);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardServesDomain#remove(java.lang.Object)
   */
  public void remove(final Object o) {
    if (_log.isDebugEnabled()) {
      _log.debug("remove");
    }
    try {
      // Setting the pedigree requires special privileges
      AccessController.doPrivileged(new PrivilegedAction() {
        public Object run() {
          pedigreeService.removePedigree(o);
          return null;
        }
      });
    }
    catch (Exception e) {
      if (_log.isWarnEnabled()) {
        _log.warn("Unable to remove pedigree", e);
      }
    }
    rootPlan.remove(o);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardServesDomain#change(java.lang.Object, java.util.Collection)
   */
  public void change(Object o, Collection changes) {
    setPedigree(o, PUBLISH_CHANGE);;
    rootPlan.change(o, changes);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardServesDomain#sendDirective(org.cougaar.core.blackboard.Directive)
   */
  public void sendDirective(Directive dir) {
    if (_log.isDebugEnabled()) {
      _log.debug("sendDirective");
    }
    rootPlan.sendDirective(dir);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardServesDomain#sendDirective(org.cougaar.core.blackboard.Directive, java.util.Collection)
   */
  public void sendDirective(Directive dir, Collection changeReports) {
    if (_log.isDebugEnabled()) {
      _log.debug("sendDirective");
    }
    rootPlan.sendDirective(dir, changeReports);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardServesDomain#getHistory()
   */
  public PublishHistory getHistory() {
    if (_log.isDebugEnabled()) {
      _log.debug("getHistory");
    }
    return rootPlan.getHistory();
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardServesDomain#getABATranslation(org.cougaar.multicast.AttributeBasedAddress)
   */
  public ABATranslation getABATranslation(AttributeBasedAddress aba) {
    if (_log.isDebugEnabled()) {
      _log.debug("getABATranslation");
    }
    return rootPlan.getABATranslation(aba);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.domain.XPlan#setupSubscriptions(org.cougaar.core.blackboard.Blackboard)
   */
  public void setupSubscriptions(Blackboard alpPlan) {
    if (_log.isDebugEnabled()) {
      _log.debug("setupSubscriptions");
    }
    rootPlan.setupSubscriptions(alpPlan);
  }
  
  private static final int PUBLISH_ADD = 1;
  private static final int PUBLISH_CHANGE = 2;
  private static final int PUBLISH_REMOVE = 3;
  
  private void setPedigree(final Object o, int type) {
    try {
      final Pedigree p = pedigreeHandler.getThreadLocalPedigree();
      if (_log.isDebugEnabled()) {
        _log.debug("Set pedigree: " + p);
      }
      if (p == null) {
        if (_log.isDebugEnabled()) {
          _log.debug("No pedigree found - Type=" + type, new Throwable());
        }
      }
      // Setting the pedigree requires special privileges
      AccessController.doPrivileged(new PrivilegedAction() {
        public Object run() {
          if (p != null) {
            pedigreeService.setPedigree(o, p);
          }
          return null;
        }
      });
    }
    catch (Exception e) {
      if (_log.isWarnEnabled()) {
        _log.warn("Unable to set pedigree", e);
      }
    }
  }
}
