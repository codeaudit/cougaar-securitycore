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
import org.cougaar.core.service.BlackboardQueryService;
import org.cougaar.core.component.Service;
import org.cougaar.core.blackboard.Subscriber;
import org.cougaar.core.blackboard.Subscription;
import org.cougaar.core.blackboard.SubscriberException;
import org.cougaar.core.blackboard.SubscriptionWatcher;
import org.cougaar.core.persist.PersistenceNotEnabledException;
import org.cougaar.core.persist.Persistence;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.mts.MessageAddress;

import org.cougaar.core.component.BindingSite;
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
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.acl.auth.UserRoles;


/**
 * A BlackboardService proxy that protects the blackboard
 * from certain users executing specific actions.
 *
 * Add a line like the following to a agent.ini file:
 * <pre>
 * Node.AgentManager.Agent.PluginManager.Binder = org.cougaar.core.security.acl.auth.blackboard.BBSelectFilter
 * </pre>
 **/
public class BBSelectFilter extends BlackboardFilter {

  static BlackboardGuard _bbg = null;

  public BBSelectFilter() {
    super(BBSelectFilterBinder.class);
  }

  public void setParameter(Object o) {
  }

  public void setBindingSite(BindingSite bs) {
    super.setBindingSite(bs);
    synchronized (BBSelectFilter.class) {
      if (_bbg == null) {
        _bbg = new BlackboardGuard(bs.getServiceBroker());
      }
    }
  }

  // This is a "Wrapper" binder which installs a service filter for plugins
  public static class BBSelectFilterBinder 
    extends BlackboardFilter.PluginServiceFilterBinder {

    public BBSelectFilterBinder(BinderFactory bf, Object child) {
      super(bf,child);
    }

    protected BlackboardService getBlackboardServiceProxy(BlackboardService bbs,
                                                          Object child) {
      MessageAddress address = getPluginManager().getAgentIdentifier();
      return new BBSelectProxy(bbs, address.getAddress(),
				 getServiceBroker());
    }

    protected BlackboardQueryService getBlackboardQueryServiceProxy(BlackboardQueryService bbs,
                                                          Object child) {
      MessageAddress address = getPluginManager().getAgentIdentifier();
      return new BBSelectQuery(bbs, address.getAddress(),
				 getServiceBroker());
    }

    public void setParameter(Object o) {
    }
  }

  // this class is a proxy for the blackboard service which audits subscription
  // requests.
  public static class BBSelectProxy
    implements BlackboardService {
    private BlackboardService _bbs;
    private String            _agentName;
    private ServiceBroker     _serviceBroker;

    public BBSelectProxy(BlackboardService service, String agentName,
      ServiceBroker sb) {
      _bbs = service;
      _agentName = agentName;
      _serviceBroker = sb;
    }

    private void checkAccess(String method) {
      if (!_bbg.canAccess(_agentName,method)) {
        throw new BlackboardAccessException("The user does not have permission to access BlackboardService method (" + method + ")");
      }
    }

    public void closeTransactionDontReset() {
      checkAccess("closeTransaction");
      _bbs.closeTransactionDontReset();
    }

    public void closeTransaction() {
      checkAccess("closeTransaction");
      _bbs.closeTransaction();
    }
    
    /** @deprecated Use {@link #closeTransactionDontReset closeTransactionDontReset}
     **/
    public void closeTransaction(boolean reset) {
      checkAccess("closeTransaction");
      if (!reset) {
        closeTransactionDontReset();
      } else {
        _bbs.closeTransaction();
      }
    }
    
    public boolean didRehydrate() {
      checkAccess("didRehydrate");
      return _bbs.didRehydrate();
    }

    public Persistence getPersistence() {
      checkAccess("getPersistence");
      return _bbs.getPersistence();
    }

    public Subscription subscribe(Subscription s) {
      checkAccess("subscribe");
      return _bbs.subscribe(s);
    }

    public Subscription subscribe(UnaryPredicate isMember) {
      checkAccess("subscribe");
      return _bbs.subscribe(isMember);
    }

    public Subscription subscribe(UnaryPredicate isMember, Collection realCollection){
      checkAccess("subscribe");
      return _bbs.subscribe(isMember, realCollection);
    }

    public Subscription subscribe(UnaryPredicate isMember, boolean isIncremental) {
      checkAccess("subscribe");
      return _bbs.subscribe(isMember, isIncremental);
    }
  
    public Subscription subscribe(UnaryPredicate isMember, Collection realCollection, 
                           boolean isIncremental) {
      checkAccess("subscribe");
      return _bbs.subscribe(isMember, realCollection, isIncremental);
    }

    public Collection query(UnaryPredicate isMember) {
      checkAccess("query");
      return _bbs.query(isMember);
    }

    public void unsubscribe(Subscription subscription) {
      checkAccess("unsubscribe");
      _bbs.unsubscribe(subscription);
    }
  
    public int getSubscriptionCount() {
      checkAccess("getSubscriptionCount");
      return _bbs.getSubscriptionCount();
    }
  
    public int getSubscriptionSize() {
      checkAccess("getSubscriptionSize");
      return _bbs.getSubscriptionSize();
    }
    
    public int getPublishAddedCount() {
      checkAccess("getPublishAddedCount");
      return _bbs.getPublishAddedCount();
    }

    public int getPublishChangedCount(){
      checkAccess("getPublishChangedCount");
      return _bbs.getPublishChangedCount();
    }
    
    public int getPublishRemovedCount(){
      checkAccess("getPublishRemovedCount");
      return _bbs.getPublishRemovedCount();
    }
    
    public boolean haveCollectionsChanged(){
      checkAccess("haveCollectionsChanged");
      return _bbs.haveCollectionsChanged();
    }

    public boolean publishAdd(Object o){
      checkAccess("publishAdd");
      return _bbs.publishAdd(o);
    }
    
    public boolean publishRemove(Object o){
      checkAccess("publishRemove");
      return _bbs.publishRemove(o);
    }
    
    public boolean publishChange(Object o) {
      checkAccess("publishChange");
      return _bbs.publishChange(o);
    }
    
    public boolean publishChange(Object o, Collection changes) {
      checkAccess("publishChange");
      return _bbs.publishChange(o,changes);
    } 

    public void openTransaction() {
      checkAccess("openTransaction");
      _bbs.openTransaction();
    }

    public boolean tryOpenTransaction() {
      checkAccess("tryOpenTransaction");
      return _bbs.tryOpenTransaction();
    }

    public void signalClientActivity() {
      checkAccess("signalClientActivity");
      _bbs.signalClientActivity();
    }

    public SubscriptionWatcher registerInterest(SubscriptionWatcher w) {
      checkAccess("registerInterest");
      return _bbs.registerInterest(w);
    }

    public SubscriptionWatcher registerInterest() {
      checkAccess("registerInterest");
      return _bbs.registerInterest();
    }

    public void unregisterInterest(SubscriptionWatcher w) throws SubscriberException {
      checkAccess("unregisterInterest");
      _bbs.unregisterInterest(w);
    }

    public void setShouldBePersisted(boolean value) {
      checkAccess("setShouldBePersisted");
      _bbs.setShouldBePersisted(value);
    }

    public boolean shouldBePersisted() {
      checkAccess("shouldBePersisted");
      return _bbs.shouldBePersisted();
    }

    public void persistNow() throws PersistenceNotEnabledException {
      checkAccess("persistNow");
      _bbs.persistNow();
    }

    public Subscriber getSubscriber() {
      checkAccess("getSubscriber");
      return _bbs.getSubscriber();
    }
  }

  public static class BBSelectQuery
    implements BlackboardQueryService {
    private BlackboardQueryService _bbs;
    private String            _agentName;
    private ServiceBroker     _serviceBroker;

    public BBSelectQuery(BlackboardQueryService service, String agentName,
                           ServiceBroker sb) {
      _bbs = service;
      _agentName = agentName;
      _serviceBroker = sb;
    }

    public Collection query(UnaryPredicate isMember) {
      if (!_bbg.canAccess(_agentName,"query")) {
        throw new BlackboardAccessException("The user does not have neaded to access BlackboardQueryService query method");
      }
      return _bbs.query(isMember);
    }
  }

  public static class BlackboardGuard 
    extends GuardRegistration 
    implements NodeEnforcer {

    HashMap _ruleMap = new HashMap();

    public BlackboardGuard(ServiceBroker sb) {
      super(BlackboardFilterPolicy.class.getName(), "BBSelectFilter",
	    sb);
      try {
        registerEnforcer();
      } catch (Exception ex) {
        // FIXME: Shouldn't just let this drop, I think
        ex.printStackTrace();
      }
    }

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
      log.warn("receivePolicyMessage(Policy...) should not be called");
    }
    /**
     * Merges an existing policy with a new policy.
     * @param policy the new policy to be added
     */
    public void receivePolicyMessage(SecurityPolicy policy,
                                     String policyID,
                                     String policyName,
                                     String policyDescription,
                                     String policyScope,
                                     String policySubjectID,
                                     String policySubjectName,
                                     String policyTargetID,
                                     String policyTargetName,
                                     String policyType) {
      if (policy == null || !(policy instanceof BlackboardFilterPolicy)) {
        return;
      }

      if (log.isDebugEnabled()) {
        log.debug("ProxyBlackboard: Received policy message");
        log.debug(policy.toString());
      }
      BlackboardFilterPolicy bbPolicy = (BlackboardFilterPolicy) policy;
      HashMap map = new HashMap();
      BlackboardFilterPolicy.SelectRule[] rules = bbPolicy.getSelectRules();
      for (int i = 0; i < rules.length; i++) {
        BlackboardFilterPolicy.SelectRule rule = rules[i];
        HashMap methodMap = getMap(map, rules[i].agent);
        Iterator iter = rule.methods.iterator();
        while (iter.hasNext()) {
          String method = (String) iter.next();
          HashMap patternMap = getMap(methodMap, method);

          Iterator jter = rule.patterns.iterator();

          while (jter.hasNext()) {
            String pattern = (String) jter.next();
            HashSet roles = (HashSet) patternMap.get(pattern);
            if (roles == null) {
              roles = new HashSet();
              patternMap.put(pattern,roles);
            }
            Iterator kter = rule.roles.iterator();
            while (kter.hasNext()) {
              roles.add(kter.next());
            }
          }
        }
      }
      _ruleMap = map;
    }

    private static HashMap getMap(HashMap map, String index) {
      HashMap m = (HashMap) map.get(index);
      if (m == null) {
        m = new HashMap();
        map.put(index,m);
      }
      return m;
    }

    private boolean canAccess(String agentName, String method) {
      if (agentName == null) {
        log.debug("agentName is null");
        return true;
      }
      
      String roles[] = UserRoles.getRoles();
      if (roles == null) {
        // this isn't a servlet -- allow it.
//         log.debug("This isn't a servlet call");
        return true;
      }

      String uri = UserRoles.getURI();
      if (uri == null) {
//         log.debug("There is no uri for the user.");
        return true; // no uri for the user so not a secured servlet.
      }
      if (!uri.substring(0,agentName.length() + 2).
          equals("/$" + agentName) ||
          (uri.charAt(agentName.length() + 2) != '/' &&
           uri.length() != agentName.length() + 2)) {
        log.warn("User attempting illegal access to " + agentName +
                 " -- uri is " + uri);
        return false;
      }
      uri = uri.substring(agentName.length() + 2);

      int access = canAccess(agentName, method, uri, roles);
      if (access == 1) return true;
      int access2 = canAccess("*", method, uri, roles);
      if (access2 == 1) return true;
      if (access == 0 || access2 == 0) return false;
      return true; // no rule for this uri
    }

    public int canAccess(String agent, String method, String uri,
                         String roles[]) {
      HashMap methodMap = (HashMap)_ruleMap.get(agent);
      if (methodMap == null) return -1;

      // now go through each pattern:
      HashMap patterns = (HashMap) methodMap.get(method);
      if (patterns == null) return -1;

      Iterator iter = patterns.keySet().iterator();
      while (iter.hasNext()) {
        String pattern = (String)iter.next();
        if (matches(uri, pattern)) {
          HashSet roleMap = (HashSet) patterns.get(pattern);
          for (int i = 0; i < roles.length; i++) {
            if (roleMap.contains(roles[i])) {
              return 1;
            }
          }
          return 0;
        }
      }
      return -1;
    }

    private static boolean matches(String uri, String wild) {
      if (wild.startsWith("*")) {
        return uri.endsWith(wild.substring(1));
      }
      if (wild.endsWith("*")) {
        return uri.startsWith(wild.substring(0, wild.length()-1));
      }
      return wild.equals(uri);
    }
  }
}
