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

// KAoS
import org.cougaar.core.security.policy.GuardRegistration;
import safe.enforcer.NodeEnforcer;

// Cougaar core infrastructure
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


/**
 * The base class for BlackboardService proxies
 **/
public class BlackboardFilter extends ServiceFilter {
  Class _pluginServiceFilter;
  
  public BlackboardFilter(Class pluginServiceFilterClass) {
    _pluginServiceFilter = pluginServiceFilterClass;
  }

  /**
   *  This method specifies the Binder to use (defined later) 
   */
  protected Class getBinderClass(Object child) {
    return _pluginServiceFilter;
  }
  

  // This is a "Wrapper" binder which installs a service filter for plugins
  public abstract static class PluginServiceFilterBinder 
    extends ServiceFilterBinder {

    public PluginServiceFilterBinder(BinderFactory bf, Object child) {
      super(bf,child);
    }

    protected final PluginManagerForBinder getPluginManager() { 
      return (PluginManagerForBinder)getContainer(); 
    }

    abstract protected BlackboardService getBlackboardServiceProxy(BlackboardService bbs,
                                                                   Object client);

    abstract protected BlackboardQueryService 
      getBlackboardQueryServiceProxy(BlackboardQueryService bbs,
                                     Object client);

    // this method specifies a binder proxy to use, so as to
    // avoid exposing the binder itself to the lower level objects.
    protected ContainerAPI createContainerProxy() { 
      return new PluginFilteringBinderProxy(); 
    }

    // this method installs the "filtering" service broker
    protected ServiceBroker createFilteringServiceBroker(ServiceBroker sb) {
      return new PluginFilteringServiceBroker(sb); 
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
      public PluginFilteringServiceBroker(ServiceBroker sb) {
        super(sb);
      }

      // here's where we catch the service request for Blackboard and proxy the
      // returned service.  See FilteringServiceBroker for more options.
      protected Object getServiceProxy(Object service, Class serviceClass, Object client) {
        if (service instanceof BlackboardService) {
          return getBlackboardServiceProxy((BlackboardService) service,client);
        }
        if (service instanceof BlackboardQueryService) {
          return getBlackboardQueryServiceProxy((BlackboardQueryService) service,client);
        }

        return null;
      }
    }
  }
}
