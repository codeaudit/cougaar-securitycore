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

import org.cougaar.core.blackboard.Subscriber;
import org.cougaar.core.blackboard.SubscriberException;
import org.cougaar.core.blackboard.Subscription;
import org.cougaar.core.blackboard.SubscriptionWatcher;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.persist.Persistence;
import org.cougaar.core.persist.PersistenceNotEnabledException;
import org.cougaar.core.security.services.auth.PedigreeService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

/**
 * Manages pedigree on the BlackboardClient side.
 */
class BlackboardServiceProxy 
implements BlackboardService
{
  protected transient BlackboardService   _bs;
  private PedigreeService                 pedigreeService;
  private static Logger                   _log;
  
  static {
    _log = LoggerFactory.getInstance().createLogger(BlackboardServiceProxy.class);
  }
  
  public BlackboardServiceProxy(BlackboardService bs, final ServiceBroker sb) {
    _bs = bs;
    try {
      pedigreeService = (PedigreeService)
      AccessController.doPrivileged(new PrivilegedAction() {
        public Object run() {
          return sb.getService(this, PedigreeService.class, null);
        }
      });
    }
    catch (Exception e) {
      if (_log.isErrorEnabled()) {
        _log.error("Error while retrieving PedigreeService", e);
      }
    }
    if (pedigreeService == null) {
      if (_log.isErrorEnabled()) {
        _log.error("Unable to retrieve " + PedigreeService.class.getName());
      }
    }
  }
  public Subscriber getSubscriber() { 
    return _bs.getSubscriber();
  }
  public Subscription subscribe(UnaryPredicate isMember) { 
    return _bs.subscribe(isMember); 
  }
  public Subscription subscribe(UnaryPredicate isMember, Collection realCollection) {
    return _bs.subscribe(isMember, realCollection);
  }
  public Subscription subscribe(UnaryPredicate isMember, boolean isIncremental) {
    return _bs.subscribe(isMember, isIncremental);
  }
  public Subscription subscribe(UnaryPredicate isMember, Collection realCollection, boolean isIncremental) {
    return _bs.subscribe(isMember, realCollection, isIncremental);
  }
  public Subscription subscribe(Subscription subscription) {
    return _bs.subscribe(subscription);
  }
  
  public Collection query(UnaryPredicate isMember) {
    return _bs.query(isMember);
  }
  public void unsubscribe(Subscription subscription) {
    _bs.unsubscribe(subscription);
  }
  public int getSubscriptionCount() {
    return _bs.getSubscriptionCount();
  }
  public int getSubscriptionSize() {
    return _bs.getSubscriptionSize();
  }
  public int getPublishAddedCount() {
    return _bs.getPublishAddedCount();
  }
  public int getPublishChangedCount() {
    return _bs.getPublishChangedCount();
  }
  public int getPublishRemovedCount() {
    return _bs.getPublishRemovedCount();
  }
  public boolean haveCollectionsChanged() {
    return _bs.haveCollectionsChanged();
  }
  
  public void publishAdd(Object o) {
    _bs.publishAdd(o);
  }
  
  public void publishRemove(Object o) {
    // Invoke PedigreeService to remove pedigree.
    pedigreeService.removePedigree(o);
    _bs.publishRemove(o);
  }
  public void publishChange(Object o) {
    _bs.publishChange(o);
  }
  public void publishChange(Object o, Collection changes) {
    _bs.publishChange(o, changes);
  }
  public void openTransaction() {
    _bs.openTransaction();
  }
  public boolean tryOpenTransaction() {
    return _bs.tryOpenTransaction();
  }
  public void closeTransaction() throws SubscriberException {
    _bs.closeTransaction();
  }
  public void closeTransactionDontReset() throws SubscriberException {
    _bs.closeTransactionDontReset();
  }
  /** 
   *@deprecated Use {@link #closeTransactionDontReset closeTransactionDontReset}
   */
  public void closeTransaction(boolean resetp) throws SubscriberException {
    _bs.closeTransaction(resetp);
  }
  public boolean isTransactionOpen() {
    return _bs.isTransactionOpen();
  }
  public void signalClientActivity() {
    _bs.signalClientActivity();
  }
  public SubscriptionWatcher registerInterest(SubscriptionWatcher w) {
    return _bs.registerInterest(w);
  }
  public SubscriptionWatcher registerInterest() {
    return _bs.registerInterest();
  }
  public void unregisterInterest(SubscriptionWatcher w) throws SubscriberException {
    _bs.unregisterInterest(w);
  }
  public void setShouldBePersisted(boolean value) {
    _bs.setShouldBePersisted(value);
  }
  public boolean shouldBePersisted() {
    return _bs.shouldBePersisted();
  }
  public void persistNow() throws PersistenceNotEnabledException {
    _bs.persistNow();
  }
  public boolean didRehydrate() {
    return _bs.didRehydrate();
  }
  public Persistence getPersistence() {
    return _bs.getPersistence();
  }
  
}
