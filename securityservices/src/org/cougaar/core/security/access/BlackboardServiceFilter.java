/**
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
 * Created on March 21, 2002, 10:38 AM
 */

package org.cougaar.core.security.access;

import java.util.*;
import org.cougaar.util.*;
import org.cougaar.core.component.*;
import org.cougaar.core.agent.*;
import org.cougaar.core.domain.*;
import org.cougaar.core.blackboard.*;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.persist.*;
import org.cougaar.core.blackboard.*;
import org.cougaar.core.plugin.PluginManagerForBinder;
import org.cougaar.core.service.BlackboardService;

public class BlackboardServiceFilter extends ServiceFilter{

  //  This method specifies the Binder to use (defined later)
  protected Class getBinderClass(Object child) {
    return BlackboardServiceFilterBinder.class;
  }
  
  //this is here as a patch
  public void setParameter(Object o) {}

  // This is a "Wrapper" binder which installs a service filter for plugins
  public static class BlackboardServiceFilterBinder
    extends ServiceFilterBinder
  {
    public BlackboardServiceFilterBinder(BinderFactory bf, Object child) {
      super(bf,child);
    }

    protected final PluginManagerForBinder getPluginManager() { return (PluginManagerForBinder)getContainer(); }

    // this method specifies a binder proxy to use, so as to avoid exposing the binder
    // itself to the lower level objects.
    protected ContainerAPI createContainerProxy() { return new PluginFilteringBinderProxy(); }

    // this method installs the "filtering" service broker
    protected ServiceBroker createFilteringServiceBroker(ServiceBroker sb) {
      return new PluginFilteringServiceBroker(sb); 
    }

    // this class implements a simple proxy for a plugin wrapper binder
    protected class PluginFilteringBinderProxy
      extends ServiceFilterContainerProxy
      implements PluginManagerForBinder
    {
      public MessageAddress getAgentIdentifier() { return getPluginManager().getAgentIdentifier(); }
      public ConfigFinder getConfigFinder() { return getPluginManager().getConfigFinder(); }
    }


    // this class catches requests for blackboard services, and 
    // installs its own service proxy.
    protected class PluginFilteringServiceBroker 
      extends FilteringServiceBroker
    {
      public PluginFilteringServiceBroker(ServiceBroker sb) {
        super(sb);
      }
      // here's where we catch the service request for Blackboard and proxy the
      // returned service.  See FilteringServiceBroker for more options.
      protected Object getServiceProxy(Object service, Class serviceClass, Object client) {
        if (service instanceof BlackboardService) {
          return new BlackboardServiceProxy((BlackboardService) service, client);
        } 
        return null;
      }
    }
  }

  // this class is a proxy for the blackboard service which audits subscription
  // requests.
  public static class BlackboardServiceProxy implements BlackboardService {
    private BlackboardService bs;
    private Object client;
    public BlackboardServiceProxy(BlackboardService bs, Object client) {
      this.bs = bs;
      this.client=client;
    }
    public Subscriber getSubscriber() { 
      //System.err.println("Warning: "+client+" is calling BlackboardService.getSubscriber()!");
      return bs.getSubscriber();
    }
    public Subscription subscribe(Subscription s) {
      return bs.subscribe(s);
    }
    public Subscription subscribe(UnaryPredicate isMember) { 
      //System.err.println("BlackboardService.subscribe("+isMember+") called by: "+client);
      return bs.subscribe(isMember); 
    }
    public Subscription subscribe(UnaryPredicate isMember, Collection realCollection) {
      return bs.subscribe(isMember, realCollection);
    }
    public Subscription subscribe(UnaryPredicate isMember, boolean isIncremental) {
      return bs.subscribe(isMember, isIncremental);
    }
    public Subscription subscribe(UnaryPredicate isMember, Collection realCollection, boolean isIncremental) {
      return bs.subscribe(isMember, realCollection, isIncremental);
    }
    public Collection query(UnaryPredicate isMember) {
      return bs.query(isMember);
    }
    public void unsubscribe(Subscription subscription) {
      bs.unsubscribe(subscription);
    }
    public int getSubscriptionCount() {
      return bs.getSubscriptionCount();
    }
    public int getSubscriptionSize() {
      return bs.getSubscriptionSize();
    }
    public int getPublishAddedCount() {
      return bs.getPublishAddedCount();
    }
    public int getPublishChangedCount() {
      return bs.getPublishChangedCount();
    }
    public int getPublishRemovedCount() {
      return bs.getPublishRemovedCount();
    }
    public boolean haveCollectionsChanged() {
      return bs.haveCollectionsChanged();
    }
    public boolean publishAdd(Object o) {
      return bs.publishAdd(o);
    }
    public boolean publishRemove(Object o) {
      return bs.publishRemove(o);
    }
    public boolean publishChange(Object o) {
      return bs.publishChange(o);
    }
    public boolean publishChange(Object o, Collection changes) {
      return bs.publishChange(o,changes);
    }
    public void openTransaction() {
      bs.openTransaction();
    }
    public boolean tryOpenTransaction() {
      return bs.tryOpenTransaction();
    }
    public void closeTransaction() throws SubscriberException {
      bs.closeTransaction();
    }
    public void closeTransaction(boolean resetp) throws SubscriberException {
      // Method is deprecated.
      bs.closeTransactionDontReset();
    }
    public void closeTransactionDontReset() {
      bs.closeTransactionDontReset();
    }

    public void signalClientActivity() {
      bs.signalClientActivity();
    }
    public SubscriptionWatcher registerInterest(SubscriptionWatcher w) {
      return bs.registerInterest(w);
    }
    public SubscriptionWatcher registerInterest() {
      return bs.registerInterest();
    }
    public void unregisterInterest(SubscriptionWatcher w) throws SubscriberException {
      bs.unregisterInterest(w);
    }
    public void setShouldBePersisted(boolean value) {
      bs.setShouldBePersisted(value);
    }
    public boolean shouldBePersisted() {
      return bs.shouldBePersisted();
    }
    public void persistNow() throws org.cougaar.core.persist.PersistenceNotEnabledException {
      bs.persistNow();
    }
    public boolean didRehydrate() {
      return bs.didRehydrate();
    }
    public Persistence getPersistence() {
      return bs.getPersistence();
    }
  }

}
