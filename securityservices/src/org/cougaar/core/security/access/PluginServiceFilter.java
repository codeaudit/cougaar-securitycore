/**
 * <copyright>
 *  Copyright 1997-2003 Networks Associates Technology, Inc.
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

import java.util.*;
import java.io.IOException;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.cougaar.util.*;
import org.cougaar.core.component.*;
import org.cougaar.core.agent.*;
import org.cougaar.core.domain.*;
import org.cougaar.core.blackboard.*;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.persist.*;
import org.cougaar.core.blackboard.*;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.SchedulerService;
import org.cougaar.core.service.ServletService;

import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.services.auth.SecurityContextService;

public class PluginServiceFilter extends ServiceFilter {
  // for Trigger to SecurityTrigger mapping
  private static Hashtable _triggerTable = new Hashtable();
  // for ServiceListener to SecurityServiceListener mapping
  private static Hashtable _slTable = new Hashtable();
  // for servlet to SecurityServlet mapping
  private static Hashtable _servletTable = new Hashtable();
  
  //  This method specifies the Binder to use (defined later)
  protected Class getBinderClass(Object child) {
    return PluginServiceFilterBinder.class;
  }
  
  //this is here as a patch
  public void setParameter(Object o) {}

  // This is a "Wrapper" binder which installs a service filter for plugins
  public static class PluginServiceFilterBinder
    extends ServiceFilterBinder
  {
    public PluginServiceFilterBinder(BinderFactory bf, Object child) {
      super(bf,child);
    }

    // this method specifies a binder proxy to use, so as to avoid exposing the binder
    // itself to the lower level objects.
    protected ContainerAPI createContainerProxy() { return new ServiceFilterContainerProxy(); }

    // this method installs the "filtering" service broker
    protected ServiceBroker createFilteringServiceBroker(ServiceBroker sb) {
      return new PluginFilteringServiceBroker(sb); 
    }


    // this class catches requests for blackboard services, and 
    // installs its own service proxy.
    protected class PluginFilteringServiceBroker 
      extends FilteringServiceBroker
    {
      private ServiceBroker _sb;
      private SecurityContextService _scs;

      public PluginFilteringServiceBroker(ServiceBroker sb) {
        super(sb);
        _sb = sb;
        _scs = (SecurityContextService)
          _sb.getService(this, SecurityContextService.class, null);
      }
      
      public void addServiceListener(ServiceListener sl) {
        super.addServiceListener(addListener(sl));
      }

      public void removeServiceListener(ServiceListener sl) {
        super.removeServiceListener(removeListener(sl));
      }

      public Object getService(Object requestor, Class service, ServiceRevokedListener srl) {
        ServiceListener sl = (srl == null ? null : addListener(srl));
        return super.getService(requestor, service, (ServiceRevokedListener)sl);
      }
     
      // here's where we catch the service request for Blackboard and proxy the
      // returned service.  See FilteringServiceBroker for more options.
      protected Object getServiceProxy(Object service, Class serviceClass, Object client) {
        if (service instanceof BlackboardService) {
          return new BlackboardServiceProxy((BlackboardService) service, client);
        } 
        else if(service instanceof SchedulerService) {
          return new SchedulerServiceProxy(_scs, (SchedulerService) service, client); 
        }
        else if(service instanceof ServletService) {
          return new ServletServiceProxy(_scs, (ServletService) service, client);
        }
        return null;
      }
      
      private ServiceListener removeListener(ServiceListener sl) {
        return(ServiceListener)_slTable.remove(sl);
      }

      private ServiceListener addListener(ServiceListener sl) {
        ServiceListener securitySL = null;
        if(sl instanceof ServiceAvailableListener) {
          securitySL = new SecurityServiceAvailableListener(sl, _scs.getExecutionContext());
        }
        else if(sl instanceof ServiceRevokedListener) {
          securitySL = new SecurityServiceRevokedListener(sl, _scs.getExecutionContext());
        }
        _slTable.put(sl, securitySL);
        return securitySL;
      }

      class SecurityServiceAvailableListener
       implements ServiceAvailableListener {
        private ServiceAvailableListener _sl;
        private ExecutionContext _ec;

        public SecurityServiceAvailableListener(ServiceListener sl, ExecutionContext ec) {
          _sl = (ServiceAvailableListener)sl;
          _ec = ec;
        }
    
        public void serviceAvailable(ServiceAvailableEvent ae) {
          // set the execution context for the current thread
          _scs.setExecutionContext(_ec);
          // set the jaas context here
          _sl.serviceAvailable(ae);
          // reset the execution context for the current thread
          _scs.resetExecutionContext();
        }
      } // end SecurityServiceAvailableListener

      class SecurityServiceRevokedListener
        implements ServiceRevokedListener {
        private ServiceRevokedListener _sl;
        private ExecutionContext _ec;

        public SecurityServiceRevokedListener(ServiceListener sl, ExecutionContext ec) {
          _sl = (ServiceRevokedListener)sl;
          _ec = ec;
        }
    
        public void serviceRevoked(ServiceRevokedEvent re) {
          // set the execution context for the current thread
          _scs.setExecutionContext(_ec);
          // set the jaas context here
          _sl.serviceRevoked(re);
          // reset the execution context for the current thread
          _scs.resetExecutionContext();
        }
      } // end SecurityServiceRevokedListener
    } // end PluginFilteringServiceBroker 
  } // end PluginServiceFilterBinder

  /** proxy class to shield the real scheduler from clients **/
  private static class SchedulerServiceProxy implements SchedulerService {
      private SecurityContextService _scs;
    private SchedulerService _scheduler;
    private Object _requestor;
    
    SchedulerServiceProxy(SecurityContextService scs, SchedulerService ss, Object req) {
      _scs = scs;
      _scheduler = ss;
      _requestor = req;
    }
    public Trigger register(Trigger t) {
      return _scheduler.register(addTrigger(t));
    }
    
    public void unregister(Trigger t) {
      _scheduler.unregister(removeTrigger(t));
    }
    
    private Trigger addTrigger(Trigger t) {
      Trigger st = new SecurityTrigger(t, _scs.getExecutionContext());
      _triggerTable.put(t, st);
      return st;
    }
    
    private Trigger removeTrigger(Trigger t) {
      return(Trigger)_triggerTable.remove(t); 
    }
    
    private class SecurityTrigger implements Trigger {
      private Trigger _trigger;
      private ExecutionContext _ec;
      public SecurityTrigger(Trigger t, ExecutionContext ec) {
        _trigger = t;
        _ec = ec;
      }
      public void trigger() {
        _scs.setExecutionContext(_ec);
        // set the jaas context here
        _trigger.trigger();
        _scs.resetExecutionContext();
      }
    } // end SecurityTrigger
  } // end SchedulerServiceProxy
 
  private static class ServletServiceProxy implements ServletService {
    private SecurityContextService _scs;
    private ServletService _ss;
    private Object _requestor;
    
    public ServletServiceProxy(SecurityContextService scs, ServletService ss, Object req) {
      _scs = scs;
      _ss = ss;
      _requestor = req;  
    }
    public int getHttpPort() {
      return _ss.getHttpPort();
    }
    public int getHttpsPort() {
      return _ss.getHttpsPort();
    }
    public void register(String path, Servlet servlet) 
      throws Exception {
      _ss.register(path, addServlet(path, servlet));
    }
    public void unregister(String path) {
      removeServlet(path);
      _ss.unregister(path);
    }
    public void unregisterAll() {
      removeAll();
      _ss.unregisterAll();  
    }
    
    private Servlet addServlet(String path, Servlet servlet) {
      Servlet ss = new SecurityServlet(_scs.getExecutionContext(), servlet);
      _servletTable.put(path, ss); 
      return ss;
    }
    private Servlet removeServlet(String path) {
      return (Servlet)_servletTable.remove(path);
    }
    private void removeAll() {
      _servletTable.clear();
    }
    
    private class SecurityServlet implements Servlet {
      private ExecutionContext _ec;
      private Servlet _servlet;
      
      public SecurityServlet(ExecutionContext ec, Servlet servlet) {
        _ec = ec;
        _servlet = servlet;
      }
      
      public void destroy() {
        _servlet.destroy(); 
      }
         
      public ServletConfig getServletConfig() {
        return _servlet.getServletConfig();
      }
      
      public String getServletInfo() {
        return _servlet.getServletInfo();
      }
      
      public void init(ServletConfig config) 
        throws ServletException {
        _servlet.init(config);
      }
      
      public void service(ServletRequest req, ServletResponse res) 
        throws ServletException, IOException {
        _scs.setExecutionContext(_ec);
        // add to jaas context
        _servlet.service(req, res);
        _scs.resetExecutionContext();
      }
    }
  }
  
  // this class is a proxy for the blackboard service which audits subscription
  // requests.
  private static class BlackboardServiceProxy implements BlackboardService {
    private BlackboardService _bs;
    private Object _client;
    public BlackboardServiceProxy(BlackboardService bs, Object client) {
       _bs = bs;
      _client = client;
    }
    public Subscriber getSubscriber() { 
      return _bs.getSubscriber();
    }
    public Subscription subscribe(Subscription s) {
      return _bs.subscribe(s);
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
      _bs.publishRemove(o);
    }
    public void publishChange(Object o) {
      _bs.publishChange(o);
    }
    public void publishChange(Object o, Collection changes) {
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
    public void closeTransaction(boolean resetp) throws SubscriberException {
      // Method is deprecated.
      _bs.closeTransactionDontReset();
    }
    public void closeTransactionDontReset() {
      _bs.closeTransactionDontReset();
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
    public void persistNow() throws org.cougaar.core.persist.PersistenceNotEnabledException {
      _bs.persistNow();
    }
    public boolean didRehydrate() {
      return _bs.didRehydrate();
    }
    public Persistence getPersistence() {
      return _bs.getPersistence();
    }
  }

}
