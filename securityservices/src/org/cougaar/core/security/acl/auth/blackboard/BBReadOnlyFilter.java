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

package org.cougaar.core.security.acl.auth.blackboard;

import java.util.HashMap;
import java.util.HashSet;
import java.security.Principal;
import java.util.Collection;
import java.util.ArrayList;
import java.util.Iterator;
import java.lang.reflect.Modifier;
import java.lang.reflect.Method;

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
import org.cougaar.planning.ldm.policy.KeyRuleParameterEntry;
import org.cougaar.planning.ldm.policy.KeyRuleParameter;

// Cougaar security services
import org.cougaar.core.security.policy.BlackboardFilterPolicy;
import org.cougaar.core.security.acl.auth.UserRoles;


/**
 * A BlackboardService proxy that protects the blackboard
 * from certain users doing write access when they should
 * only have read-only access.
 *
 * Add a line like the following to a agent.ini file:
 * <pre>
 * Node.AgentManager.Agent.PluginManager.Binder = org.cougaar.core.security.acl.auth.blackboard.BBReadOnlyFilter
 * </pre>
 **/
public class BBReadOnlyFilter extends BlackboardFilter {

  public BBReadOnlyFilter() {
    super(BBReadOnlyFilterBinder.class);
  }

  // This is a "Wrapper" binder which installs a service filter for plugins
  public class BBReadOnlyFilterBinder 
    extends BlackboardFilter.PluginServiceFilterBinder {

    public BBReadOnlyFilterBinder(BinderFactory bf, Object child) {
      super(bf,child);
    }

    protected BlackboardService getBlackboardServiceProxy(BlackboardService bbs,
                                                          Object child) {
      MessageAddress address = getPluginManager().getAgentIdentifier();
      return new BBReadOnlyProxy(bbs, address.getAddress(),
				 getServiceBroker());
    }
  }

  // this class is a proxy for the blackboard service which audits subscription
  // requests.
  public class BBReadOnlyProxy
    implements BlackboardService {
    private BlackboardGuard   _bbg;
    private BlackboardService _bbs;
    private String            _agentName;
    private ServiceBroker     _serviceBroker;

    public BBReadOnlyProxy(BlackboardService service, String agentName,
      ServiceBroker sb) {
      _bbs = service;
      _agentName = agentName;
      _serviceBroker = sb;
      _bbg = new BlackboardGuard(_serviceBroker);
    }

    private void checkWrite(String method) {
      if (!_bbg.canWrite(_agentName)) {
        throw new BlackboardAccessException("The user does not have write permission neaded to access BlackboardService method (" + method + ")");
      }
    }

    public void closeTransactionDontReset() {
      checkWrite("closeTransaction");
      _bbs.closeTransactionDontReset();
    }

    public void closeTransaction() {
      checkWrite("closeTransaction");
      _bbs.closeTransaction();
    }
    
    public void closeTransaction(boolean resetp) {
      checkWrite("closeTransaction");
      _bbs.closeTransaction(resetp);
    }

    public boolean didRehydrate() {
//       checkWrite("didRehydrate");
      return _bbs.didRehydrate();
    }

    public Persistence getPersistence() {
      checkWrite("getPersistence");
      return _bbs.getPersistence();
    }

    public Subscription subscribe(Subscription s) {
      checkWrite("subscribe");
      return _bbs.subscribe(s);
    }

    public Subscription subscribe(UnaryPredicate isMember) {
      checkWrite("subscribe");
      return _bbs.subscribe(isMember);
    }

    public Subscription subscribe(UnaryPredicate isMember, Collection realCollection){
      checkWrite("subscribe");
      return _bbs.subscribe(isMember, realCollection);
    }

    public Subscription subscribe(UnaryPredicate isMember, boolean isIncremental) {
      checkWrite("subscribe");
      return _bbs.subscribe(isMember, isIncremental);
    }
  
    public Subscription subscribe(UnaryPredicate isMember, Collection realCollection, 
                           boolean isIncremental) {
      checkWrite("subscribe");
      return _bbs.subscribe(isMember, realCollection, isIncremental);
    }

    public Collection query(UnaryPredicate isMember) {
      if (_bbg.canWrite(_agentName)) {
        return _bbs.query(isMember);
      } else if (!_bbg.canRead(_agentName)) {
        throw new BlackboardAccessException("query");
      }

      Collection col = _bbs.query(isMember);
      ArrayList newList = new ArrayList();
      Iterator iter = col.iterator();
      while (iter.hasNext()) {
        Object o = iter.next();
        if (o instanceof Cloneable) {
          try {
            Class c = o.getClass();
            Method m = c.getMethod("clone", null);
            if ((m.getModifiers() & Modifier.PUBLIC) == Modifier.PUBLIC) {
              o = m.invoke(o, null);
            }
          } catch (Exception e) {
            // just use the original object
          }
        }
        newList.add(o);
      }
      return newList;
    }

    public void unsubscribe(Subscription subscription) {
      checkWrite("unsubscribe");
      _bbs.unsubscribe(subscription);
    }
  
    public int getSubscriptionCount() {
//       checkWrite("getSubscriptionCount");
      return _bbs.getSubscriptionCount();
    }
  
    public int getSubscriptionSize() {
//       checkWrite("getSubscriptionSize");
      return _bbs.getSubscriptionSize();
    }
    
    public int getPublishAddedCount() {
//       checkWrite("getPublishAddedCount");
      return _bbs.getPublishAddedCount();
    }

    public int getPublishChangedCount(){
//       checkWrite("getPublishChangedCount");
      return _bbs.getPublishChangedCount();
    }
    
    public int getPublishRemovedCount(){
//       checkWrite("getPublishRemovedCount");
      return _bbs.getPublishRemovedCount();
    }
    
    public boolean haveCollectionsChanged(){
//       checkWrite("haveCollectionsChanged");
      return _bbs.haveCollectionsChanged();
    }

    public boolean publishAdd(Object o){
      checkWrite("publishAdd");
      return _bbs.publishAdd(o);
    }
    
    public boolean publishRemove(Object o){
      checkWrite("publishRemove");
      return _bbs.publishRemove(o);
    }
    
    public boolean publishChange(Object o) {
      checkWrite("publishChange");
      return _bbs.publishChange(o);
    }
    
    public boolean publishChange(Object o, Collection changes) {
      checkWrite("publishChange");
      return _bbs.publishChange(o,changes);
    } 

    public void openTransaction() {
      checkWrite("openTransaction");
      _bbs.openTransaction();
    }

    public boolean tryOpenTransaction() {
      checkWrite("tryOpenTransaction");
      return _bbs.tryOpenTransaction();
    }

    public void signalClientActivity() {
      checkWrite("signalClientActivity");
      _bbs.signalClientActivity();
    }

    public SubscriptionWatcher registerInterest(SubscriptionWatcher w) {
      checkWrite("registerInterest");
      return _bbs.registerInterest(w);
    }

    public SubscriptionWatcher registerInterest() {
      checkWrite("registerInterest");
      return _bbs.registerInterest();
    }

    public void unregisterInterest(SubscriptionWatcher w) throws SubscriberException {
      checkWrite("unregisterInterest");
      _bbs.unregisterInterest(w);
    }

    public void setShouldBePersisted(boolean value) {
      checkWrite("setShouldBePersisted");
      _bbs.setShouldBePersisted(value);
    }

    public boolean shouldBePersisted() {
//       checkWrite("shouldBePersisted");
      return _bbs.shouldBePersisted();
    }

    public void persistNow() throws PersistenceNotEnabledException {
      checkWrite("persistNow");
      _bbs.persistNow();
    }

    public Subscriber getSubscriber() {
      checkWrite("getSubscriber");
      return _bbs.getSubscriber();
    }

  }

  public class BlackboardGuard 
    extends GuardRegistration 
    implements NodeEnforcer {

    public final static String WRITE_ROLE    = "write";
    public final static String READ_ROLE     = "read";
    public final static String DISALLOW_ROLE = "none";

    public final static String RO_RULE       = "read-only-rule";

    HashSet _read  = new HashSet();
    HashSet _write = new HashSet();

    public BlackboardGuard(ServiceBroker sb) {
      super(BlackboardFilterPolicy.class.getName(), "BBReadOnlyFilter",
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

      if (log.isDebugEnabled()) {
        log.debug("ProxyBlackboard: Received policy message");
        RuleParameter[] param = policy.getRuleParameters();
        for (int i = 0 ; i < param.length ; i++) {
          log.debug("Rule: " + param[i].getName() +
                             " - " + param[i].getValue());
        }
      }
      // what is the policy change?
      RuleParameter[] param = policy.getRuleParameters();
      synchronized (this) {
        for (int i = 0; i < param.length; i++) {
          String ruleType = param[i].getName();
          if (RO_RULE.equals(ruleType)) {
            if (!(param[i] instanceof KeyRuleParameter)) {
              log.debug("Invalid parameter type for " + 
                                 RO_RULE + ". Expecting KeySet");
            } else {
              String aName = param[i].getValue().toString();
              KeyRuleParameterEntry entries[] = 
                ((KeyRuleParameter) param[i]).getKeys();
              for (int j = 0; j < entries.length; j++) {
                String role = aName + " - " + entries[j].getKey();
                String allow = entries[j].getValue();
                if (READ_ROLE.equals(allow)) {
                  _write.remove(role);
                  _read.add(role);
                } else if (WRITE_ROLE.equals(allow)) {
                  _read.remove(role);
                  _write.add(role);
                } else if (DISALLOW_ROLE.equals(allow)) {
                  _read.remove(role);
                  _write.remove(role);
                }
              }
            }
          }
        }
      }
      }catch (Exception e) {
        e.printStackTrace();
      }
    }

    public boolean canRead(String agentName) {
      String roles[] = UserRoles.getRoles();
      if (roles != null) {
        synchronized (this) {
          for (int i = 0; i < roles.length; i++) {
            if (_read.contains(roles[i]) || _write.contains(agentName + " - " + 
                                                            roles[i])) {
              return true;
            }
          }
        }
      }
      return false;
    }

    public boolean canWrite(String agentName) {
      String roles[] = UserRoles.getRoles();
      if (roles != null) {
        synchronized (this) {
          for (int i = 0; i < roles.length; i++) {
            if (_write.contains(agentName + " - " + roles[i])) {
              return true;
            }
          }
        }
      }
      return false;
    }
  }
}
