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

import java.security.PrivilegedAction;
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
import org.cougaar.core.security.auth.JaasClient;
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
         JaasClient jc = new JaasClient();
         jc.doAs(_ec, 
                 new java.security.PrivilegedAction() {
                   public Object run() {
                     _trigger.trigger();
                     return null;
                   }
                 }, false);
        //_trigger.trigger();
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
  private static class BlackboardServiceProxy extends BlackboardServiceDelegate {
    private final Object client;
    public BlackboardServiceProxy(BlackboardService bs, Object client) {
      super(bs);
      this.client=client;
    }
    public Subscriber getSubscriber() { 
      System.err.println("Warning: "+client+" is calling BlackboardService.getSubscriber()!");
      return super.getSubscriber();
    }
    public Subscription subscribe(UnaryPredicate isMember) { 
      System.err.println("BlackboardService.subscribe("+isMember+") called by: "+client);
      return super.subscribe(isMember); 
    }
  }

  // dumb delegate, could be promoted to a reusable public class
  private static class BlackboardServiceDelegate implements BlackboardService {
    private final BlackboardService bs;
    public BlackboardServiceDelegate(BlackboardService bs) {
      this.bs = bs;
    }
    public Subscriber getSubscriber() { 
      return bs.getSubscriber();
    }
    public Subscription subscribe(UnaryPredicate isMember) { 
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
    public Subscription subscribe(Subscription subscription) {
      return bs.subscribe(subscription);
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
    public void publishAdd(Object o) {
      bs.publishAdd(o);
    }
    public void publishRemove(Object o) {
      bs.publishRemove(o);
    }
    public void publishChange(Object o) {
      bs.publishChange(o);
    }
    public void publishChange(Object o, Collection changes) {
      bs.publishChange(o,changes);
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
    public void closeTransactionDontReset() throws SubscriberException {
      bs.closeTransactionDontReset();
    }
    /** @deprecated Use {@link #closeTransactionDontReset closeTransactionDontReset}
     **/
    public void closeTransaction(boolean resetp) throws SubscriberException {
      bs.closeTransaction(resetp);
    }
    public boolean isTransactionOpen() {
      return bs.isTransactionOpen();
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
