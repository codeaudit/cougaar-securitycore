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
 *
 * Created on September 12, 2001, 10:55 AM
 */

package org.cougaar.core.security.acl.auth.test;

import java.util.HashMap;
import java.util.HashSet;
import java.security.Principal;
import java.util.Collection;

// KAoS
import org.cougaar.core.security.policy.GuardRegistration;
import safe.enforcer.NodeEnforcer;

// Cougaar core infrastructure
import org.cougaar.core.service.LoggingService;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.planning.ldm.policy.RuleParameter;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.component.Service;
import org.cougaar.core.blackboard.Subscriber;
import org.cougaar.core.blackboard.Subscription;
import org.cougaar.core.blackboard.SubscriberException;
import org.cougaar.core.blackboard.SubscriptionWatcher;
import org.cougaar.core.persist.PersistenceNotEnabledException;
import org.cougaar.core.persist.Persistence;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.mts.MessageAddress;

import org.cougaar.core.component.ServiceFilter;
import org.cougaar.core.component.ServiceFilterBinder;
import org.cougaar.core.component.ContainerAPI;
import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.plugin.PluginManagerForBinder;
import org.cougaar.util.ConfigFinder;
import org.cougaar.core.agent.ClusterIdentifier;

// Cougaar security services
import org.cougaar.core.security.policy.TypedPolicy;
import org.cougaar.core.security.acl.auth.UserRoles;


/** A plugin's view of its parent component (Container).
 * Add a line like the following to a cluster.ini file:
 * <pre>
 * Node.AgentManager.Agent.PluginManager.Binder = org.cougaar.core.security.acl.auth.test.BlackboardFilter
 * </pre>
 **/
public class BlackboardFilter extends ServiceFilter {

  private BlackboardGuard bbg;
  private LoggingService log;

  public BlackboardFilter() {
    log = (LoggingService)
	getBindingSite().getServiceBroker().
      getService(this,
		 LoggingService.class, null);
    bbg = new BlackboardGuard(getBindingSite().getServiceBroker());
  }

  public void setParameter(Object param) {
  }

  public BlackboardGuard getBlackboardGuard() {
    return bbg;
  }

  /**
   *  This method specifies the Binder to use (defined later) 
   */
  protected Class getBinderClass(Object child) {
    return PluginServiceFilterBinder.class;
  }
  

  // This is a "Wrapper" binder which installs a service filter for plugins
  public class PluginServiceFilterBinder
    extends ServiceFilterBinder {

    private BlackboardGuard bbg;

    public PluginServiceFilterBinder(BinderFactory bf, Object child) {
      super(bf,child);
      if (bf instanceof BlackboardFilter) {
	bbg = ((BlackboardFilter) bf).getBlackboardGuard();
      }
    }

    protected final PluginManagerForBinder getPluginManager() { 
      return (PluginManagerForBinder)getContainer(); 
    }

    // this method specifies a binder proxy to use, so as to
    // avoid exposing the binder itself to the lower level objects.
    protected ContainerAPI createContainerProxy() { 
      return new PluginFilteringBinderProxy(); 
    }

    // this method installs the "filtering" service broker
    protected ServiceBroker createFilteringServiceBroker(ServiceBroker sb) {
      return new PluginFilteringServiceBroker(sb, bbg); 
    }

    // this class implements a simple proxy for a plugin wrapper binder
    protected class PluginFilteringBinderProxy
      extends ServiceFilterContainerProxy
      implements PluginManagerForBinder  {

      public MessageAddress getAgentIdentifier() { 
        return getPluginManager().getAgentIdentifier(); 
      }
      public ConfigFinder getConfigFinder() { 
        return getPluginManager().getConfigFinder(); 
      }
    }


    // this class catches requests for blackboard services, and 
    // installs its own service proxy.
    protected class PluginFilteringServiceBroker 
      extends FilteringServiceBroker {
      private BlackboardGuard bbg;
      public PluginFilteringServiceBroker(ServiceBroker sb,
					  BlackboardGuard aBbg) {
        super(sb);
	bbg = aBbg;
      }

      // here's where we catch the service request for Blackboard and proxy the
      // returned service.  See FilteringServiceBroker for more options.
      protected Object getServiceProxy(Object service, Class serviceClass, Object client) {
        if (service instanceof BlackboardService) {
          return new BlackboardServiceProxy((BlackboardService) service, 
                                            bbg);
        } 
        return null;
      }
    }
  }

  // this class is a proxy for the blackboard service which audits subscription
  // requests.
  public class BlackboardServiceProxy
    implements BlackboardService {
    BlackboardService _bbs;
    BlackboardGuard   _bbg;

    public class YouCantDoThatException extends RuntimeException {}

    public BlackboardServiceProxy(BlackboardService service,
                                  BlackboardGuard bbg) {
      _bbs = service;
      _bbg = bbg;
    }

    private void checkRoles(String method) {
      if (!_bbg.allowed(method)) throw new YouCantDoThatException();
    }

    public void closeTransaction() {
      checkRoles("closeTransaction");
      _bbs.closeTransaction();
    }
    
    public void closeTransactionDontReset() {
      checkRoles("closeTransaction");
      _bbs.closeTransactionDontReset();
    }

    public void closeTransaction(boolean resetp) {
      checkRoles("closeTransaction");
      // Method is deprecated.
      _bbs.closeTransactionDontReset();
    }

    public boolean didRehydrate() {
      checkRoles("didRehydrate");
      return _bbs.didRehydrate();
    }

    public Persistence getPersistence() {
      checkRoles("getPersistence");
      return _bbs.getPersistence();
    }

    public Subscription subscribe(Subscription s) {
      checkRoles("subscribe");
      return _bbs.subscribe(s);
    }

    public Subscription subscribe(UnaryPredicate isMember) {
      checkRoles("subscribe");
      return _bbs.subscribe(isMember);
    }

    public Subscription subscribe(UnaryPredicate isMember, Collection realCollection){
      checkRoles("subscribe");
      return _bbs.subscribe(isMember, realCollection);
    }

    public Subscription subscribe(UnaryPredicate isMember, boolean isIncremental) {
      checkRoles("subscribe");
      return _bbs.subscribe(isMember, isIncremental);
    }
  
    public Subscription subscribe(UnaryPredicate isMember, Collection realCollection, 
                           boolean isIncremental) {
      checkRoles("subscribe");
      return _bbs.subscribe(isMember, realCollection, isIncremental);
    }

    public Collection query(UnaryPredicate isMember) {
      checkRoles("query");
      return _bbs.query(isMember);
    }

    public void unsubscribe(Subscription subscription) {
      checkRoles("unsubscribe");
      _bbs.unsubscribe(subscription);
    }
  
    public int getSubscriptionCount() {
      checkRoles("getSubscriptionCount");
      return _bbs.getSubscriptionCount();
    }
  
    public int getSubscriptionSize() {
      checkRoles("getSubscriptionSize");
      return _bbs.getSubscriptionSize();
    }
    
    public int getPublishAddedCount() {
      checkRoles("getPublishAddedCount");
      return _bbs.getPublishAddedCount();
    }

    public int getPublishChangedCount(){
      checkRoles("getPublishChangedCount");
      return _bbs.getPublishChangedCount();
    }
    
    public int getPublishRemovedCount(){
      checkRoles("getPublishRemovedCount");
      return _bbs.getPublishRemovedCount();
    }
    
    public boolean haveCollectionsChanged(){
      checkRoles("haveCollectionsChanged");
      return _bbs.haveCollectionsChanged();
    }

    public boolean publishAdd(Object o){
      checkRoles("publishAdd");
      return _bbs.publishAdd(o);
    }
    
    public boolean publishRemove(Object o){
      checkRoles("publishRemove");
      return _bbs.publishRemove(o);
    }
    
    public boolean publishChange(Object o) {
      checkRoles("publishChange");
      return _bbs.publishChange(o);
    }
    
    public boolean publishChange(Object o, Collection changes) {
      checkRoles("publishChange");
      return _bbs.publishChange(o,changes);
    } 

    public void openTransaction() {
      checkRoles("openTransaction");
      _bbs.openTransaction();
    }

    public boolean tryOpenTransaction() {
      checkRoles("tryOpenTransaction");
      return _bbs.tryOpenTransaction();
    }

    public void signalClientActivity() {
      checkRoles("signalClientActivity");
      _bbs.signalClientActivity();
    }

    public SubscriptionWatcher registerInterest(SubscriptionWatcher w) {
      checkRoles("registerInterest");
      return _bbs.registerInterest(w);
    }

    public SubscriptionWatcher registerInterest() {
      checkRoles("registerInterest");
      return _bbs.registerInterest();
    }

    public void unregisterInterest(SubscriptionWatcher w) throws SubscriberException {
      checkRoles("unregisterInterest");
      _bbs.unregisterInterest(w);
    }

    public void setShouldBePersisted(boolean value) {
      checkRoles("setShouldBePersisted");
      _bbs.setShouldBePersisted(value);
    }

    public boolean shouldBePersisted() {
      checkRoles("shouldBePersisted");
      return _bbs.shouldBePersisted();
    }

    public void persistNow() throws PersistenceNotEnabledException {
      checkRoles("persistNow");
      _bbs.persistNow();
    }

    public Subscriber getSubscriber() {
      checkRoles("getSubscriber");
      return _bbs.getSubscriber();
    }

  }

  public class BlackboardGuard 
    extends GuardRegistration 
    implements NodeEnforcer {

    HashMap _policies = new HashMap();

    public BlackboardGuard(ServiceBroker sb) {
      super(BlackboardPolicy.class.getName(), "BlackboardGuard",
	    sb);
      try {
        registerEnforcer();
      } catch (Exception ex) {
        // FIXME: Shouldn't just let this drop, I think
        ex.printStackTrace();
      }
    }

    /**
     * Merges an existing policy with a new policy.
     * @param policy the new policy to be added
     */
    public void receivePolicyMessage(Policy policy,
                                     String policyID,
                                     String policyName,
                                     String policyDescription,
                                     String policyScope,
                                     String policySubjectID,
                                     String policySubjectName,
                                     String policyTargetID,
                                     String policyTargetName,
                                     String policyType) {
      try {
      if (policy == null) {
        return;
      }

      if (debug) {
        System.out.println("ProxyBlackboard: Received policy message");
        RuleParameter[] param = policy.getRuleParameters();
        for (int i = 0 ; i < param.length ; i++) {
          System.out.println("Rule: " + param[i].getName() +
                             " - " + param[i].getValue());
        }
      }
      // what is the policy change?
      RuleParameter[] param = policy.getRuleParameters();
      for (int i = 0; i < param.length; i++) {
        String name  = param[i].getName();
        String value = param[i].getValue().toString();
        HashSet allowed;
        synchronized (_policies) {
          allowed = (HashSet) _policies.get(name);
          if (allowed == null) {
            allowed = new HashSet();
            _policies.put(name,allowed);
          }
        }
        synchronized (allowed) {
          allowed.add(value);
        }
      }
      }catch (Exception e) {
        e.printStackTrace();
      }
    }

    public boolean allowed(String method) {
      String roles[] = UserRoles.getRoles();
      HashSet allowed;
      synchronized (_policies) {
        allowed = (HashSet)_policies.get(method);
      }
      if (allowed == null) {
        return true;
      }

      if (roles != null) {
        synchronized (allowed) {
          for (int i = 0; i < roles.length; i++) {
            if (allowed.contains(roles[i])) {
              return true;
            }
          }
        }
      }
      return false;
    }
  }

  public class BlackboardPolicy extends TypedPolicy {
    public BlackboardPolicy() {
      super(BlackboardPolicy.class.getName());
    }
  }
}
