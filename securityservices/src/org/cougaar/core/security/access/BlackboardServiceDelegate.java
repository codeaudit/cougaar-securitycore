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

import org.cougaar.core.blackboard.Subscriber;
import org.cougaar.core.blackboard.Subscription;
import org.cougaar.core.blackboard.SubscriptionWatcher;
import org.cougaar.core.blackboard.SubscriberException;
//import org.cougaar.core.blackboard.SubscriptionWrapper;
//import org.cougaar.core.blackboard.UnaryPredicateWrapper;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.persist.Persistence;
import org.cougaar.core.persist.PersistenceNotEnabledException;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.util.UnaryPredicate;

import org.cougaar.core.security.auth.BlackboardPermission;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.JaasClient;
import org.cougaar.core.security.auth.role.RoleExecutionContext;
import org.cougaar.core.security.auth.SecuredObject;
import org.cougaar.core.security.access.bbo.SecuredOrgActivity;
import org.cougaar.glm.ldm.oplan.OrgActivity;

import java.util.Collection;
import java.util.Hashtable;
 
/**
 * Delegates to the blackboard service if component has sufficient
 * previleges to perform an add, change, remove, or query on the
 * blackboard service.
 */
class BlackboardServiceDelegate extends SecureServiceProxy 
  implements BlackboardService {
  private static Hashtable _subscriptions = new Hashtable();
  private static Hashtable _watchers = new Hashtable();
  protected BlackboardService _bs;
  
  public BlackboardServiceDelegate(BlackboardService bs, ServiceBroker sb) {
    super(sb);
    _bs = bs;
  }
  public Subscriber getSubscriber() { 
    return _bs.getSubscriber();
  }
  public Subscription subscribe(UnaryPredicate isMember) { 
    UnaryPredicate sup = 
      new SecureUnaryPredicate(isMember, _scs.getExecutionContext());
    return _bs.subscribe(sup); 
  }
  public Subscription subscribe(UnaryPredicate isMember, Collection realCollection) {
    UnaryPredicate sup = 
      new SecureUnaryPredicate(isMember, _scs.getExecutionContext());
    return _bs.subscribe(sup, realCollection);
  }
  public Subscription subscribe(UnaryPredicate isMember, boolean isIncremental) {
    UnaryPredicate sup = 
      new SecureUnaryPredicate(isMember, _scs.getExecutionContext());
    return _bs.subscribe(sup, isIncremental);
  }
  public Subscription subscribe(UnaryPredicate isMember, Collection realCollection, boolean isIncremental) {
    UnaryPredicate sup = 
      new SecureUnaryPredicate(isMember, _scs.getExecutionContext());
    return _bs.subscribe(sup, realCollection, isIncremental);
  }
  public Subscription subscribe(Subscription subscription) {
    // for now throw an exception until a wrapper for subscription is implemented
    throw new SecurityException("subscribe(Subscription) is disabled with security services"); 
    /*
    _log.debug("subscribe(Subscription) called.....");
    //return _bs.subscribe(subscription);
    // need to wrap the subscription
    UnaryPredicateWrapper upw = 
      new SecureUnaryPredicateWrapper(_scs.getExecutionContext());
    SubscriptionWrapper sw = new SubscriptionWrapper(subscription, upw);
    // allow the blackboard service to initialize the subscription
    _bs.subscribe(sw);
    // set the subscriber for the original subscription
    sw.initSubscription();
    addSubscription(subscription, sw);
    return subscription;
    */
  }
  
  public Collection query(UnaryPredicate isMember) {
    UnaryPredicate sup = new SecureUnaryPredicate(isMember, _scs.getExecutionContext());
    return _bs.query(sup);
  }
  public void unsubscribe(Subscription subscription) {
    // need to get the wrapped subscription and remove it
    //_bs.unsubscribe(removeSubscription(subscription));
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

  private static boolean isProtected(Object o) {
    // hard code for now...
    return (o instanceof org.cougaar.glm.ldm.oplan.OrgActivity);
  }

  private static SecuredObject protectObject(Object o) {
    if (o instanceof SecuredObject) {
      return (SecuredObject) o;
    }
    if (o instanceof OrgActivity) {
      return new SecuredOrgActivity((OrgActivity) o);
    }
    // can't protect anything other than OrgActivity
    // we should never get here!
    throw new RuntimeException("We should never get here");
  }

  private static String getClassName(Object o) {
    if (o instanceof OrgActivity) {
      return OrgActivity.class.getName();
    }
    return o.getClass().getName();
  }

  private static boolean isValidClass(Object o) {
    return (o instanceof SecuredOrgActivity);
  }

  private Object protectObject(Object o, String perm) {
    if (!EFFICIENT || isProtected(o)) {
      // check if the component has permission to add the object
      SecurityManager sm = System.getSecurityManager();
      if(sm != null) {
        String className = getClassName(o);
        if(_debug) {
          _log.debug("checking permission for '" +
                     perm + "' on object " + className);
        }
        BlackboardPermission bbp = new BlackboardPermission(className, perm);
        sm.checkPermission(bbp);
      }
      if (o instanceof SecuredObject) {
        if (!isValidClass(o)) {
          throw new SecurityException("You may not publish an object of " +
                                      "class " + o.getClass().getName());
        }
      } else if (EFFICIENT || isProtected(o)) {
        o = protectObject(o);
      }
    }
    return o;
  }

  public void publishAdd(Object o) {
    o = protectObject(o, "add");
    _bs.publishAdd(o);
  }

  public void publishRemove(Object o) {
    o = protectObject(o, "remove");
    _bs.publishRemove(o);
  }
  public void publishChange(Object o) {
    o = protectObject(o, "change");
    _bs.publishChange(o);
  }
  public void publishChange(Object o, Collection changes) {
    o = protectObject(o, "change");
    _bs.publishChange(o,changes);
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
    return _bs.registerInterest(addWatcher(w));
  }
  public SubscriptionWatcher registerInterest() {
    // what do we do in this case?????
    return _bs.registerInterest();
  }
  public void unregisterInterest(SubscriptionWatcher w) throws SubscriberException {
    _bs.unregisterInterest(removeWatcher(w));
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
  
  private void addSubscription(Subscription subscription, Subscription wrapper) {
    _subscriptions.put(subscription, wrapper);
  }
  private Subscription removeSubscription(Subscription subscription) {
    Subscription wrapper = (Subscription)_subscriptions.remove(subscription);
    return (wrapper != null ? wrapper : subscription);
  }
  private SubscriptionWatcher addWatcher(SubscriptionWatcher w) {
    SecureSubscriptionWatcher sw = new SecureSubscriptionWatcher(w, _scs.getExecutionContext());
    _watchers.put(w, sw);
    return sw;
  }
  private SubscriptionWatcher removeWatcher(SubscriptionWatcher w) {
    SubscriptionWatcher wrapper = (SubscriptionWatcher)_watchers.remove(w);
    return (wrapper != null ? wrapper : w);
  }
  
  protected class SecureSubscriptionWatcher 
    extends SubscriptionWatcher {
    private SubscriptionWatcher _watcher;
    private ExecutionContext _ec;
    SecureSubscriptionWatcher(SubscriptionWatcher watcher, ExecutionContext ec) {
      _watcher = watcher; 
      _ec = ec;
    }
    public boolean clearSignal() {
      // need to set this so that test() returns the correct value
      boolean retval = clientFlag || internalFlag;
      externalFlag = false;
      internalFlag = false;
      clientFlag = false;
      
      _scs.setExecutionContext(_ec);
      // set JAAS context?????
      retval = _watcher.clearSignal();
      _scs.resetExecutionContext(); 
      return retval;
    }
    public void signalNotify(int event) {
      // need to set this so that test() returns the correct value
      switch (event) {
        case EXTERNAL: externalFlag = true; break;
        case INTERNAL: internalFlag = true; break;
        case CLIENT: clientFlag = true; break;
        default: break;
      }
      _scs.setExecutionContext(_ec);
      // set JAAS context?????
      _watcher.signalNotify(event);
      _scs.resetExecutionContext();
    }
    public boolean waitForSignal() {
      boolean retval = false;
      _scs.setExecutionContext(_ec);
      // set JAAS context?????
      retval = _watcher.waitForSignal();
      _scs.resetExecutionContext(); 
      return retval;
    }
    /*
    protected boolean test() {
      boolean retval = false;
      _scs.setExecutionContext(_ec);
      // set JAAS context?????
      retval = _watcher.test();
      _scs.resetExecutionContext(); 
      return retval;       
    }
    */
  }
  /*
  protected class SecureUnaryPredicateWrapper 
    implements UnaryPredicateWrapper {
    private ExecutionContext _ec;
    public SecureUnaryPredicateWrapper(ExecutionContext ec) {
      _ec = ec;
    }
    public UnaryPredicate wrap(UnaryPredicate up) {
      _log.debug("SecureUnaryPredicateWrapper.wrap() is called.....");
      return new SecureUnaryPredicate(up, _ec);
    }
  }
  */
}
