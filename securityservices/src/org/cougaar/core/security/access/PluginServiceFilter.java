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

// core classes
import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.ContainerAPI;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceFilter;
import org.cougaar.core.component.ServiceFilterBinder;
import org.cougaar.core.component.ServiceListener;
import org.cougaar.core.component.ServiceRevokedEvent;
import org.cougaar.core.component.ServiceRevokedListener;
import org.cougaar.core.component.ServiceFilterBinder.FilteringServiceBroker;
import org.cougaar.core.qos.metrics.MetricsService;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.JaasClient;
import org.cougaar.core.security.services.auth.SecurityContextService;
import org.cougaar.core.service.AlarmService;
import org.cougaar.core.service.BlackboardMetricsService;
import org.cougaar.core.service.BlackboardQueryService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.SchedulerService;
import org.cougaar.core.service.ServletService;
import org.cougaar.core.service.ThreadControlService;
import org.cougaar.core.service.ThreadListenerService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.planning.service.PrototypeRegistryService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import java.util.Hashtable;

public class PluginServiceFilter extends ServiceFilter {
  private static Logger _log;

  static {
    _log = LoggerFactory.getInstance().createLogger(PluginServiceFilter.class);
  }

  // for ServiceListener to SecurityServiceListener mapping
  private static Hashtable _slTable = new Hashtable();

  //  This method specifies the Binder to use (defined later)
  protected Class getBinderClass(Object child) {
    return PluginServiceFilterBinder.class;
  }
  
  //this is here as a patch
  public void setParameter(Object o) {}

  public PluginServiceFilter() {
    if (_log.isDebugEnabled()) {
      _log.debug("Instantiating binder factory: " + this);
    }
  }

  // This is a "Wrapper" binder which installs a service filter for plugins
  public static class PluginServiceFilterBinder
    extends ServiceFilterBinder
  {
    public PluginServiceFilterBinder(BinderFactory bf, Object child) {
      super(bf,child);
      if (_log.isDebugEnabled()) {
        _log.debug("Instantiating binder: " + this);
      }
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
        if (_log.isDebugEnabled()) {
          _log.debug("Instantiating proxy: " + this);
        }
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
          return new BlackboardServiceProxy((BlackboardService) service, client, _sb);
        } 
        else if(service instanceof SchedulerService) {
          return new SchedulerServiceProxy((SchedulerService) service, client, _sb); 
        }
        else if(service instanceof ServletService) {
          return new ServletServiceProxy((ServletService) service, client, _sb);
        }
        else if(service instanceof AlarmService) {
          return new AlarmServiceProxy((AlarmService) service, client, _sb);
        }
        else if(service instanceof BlackboardMetricsService) {
          return new BlackboardMetricsServiceProxy((BlackboardMetricsService) service, client, _sb);
        }
        else if(service instanceof BlackboardQueryService) {
          return new BlackboardQueryServiceProxy((BlackboardQueryService) service, client, _sb);
        }
        else if(service instanceof CommunityService) {
          return new CommunityServiceProxy((CommunityService) service, client, _sb); 
        }
        else if(service instanceof MetricsService) {
          return new MetricsServiceProxy((MetricsService) service, client, _sb);           
        }
        else if(service instanceof PrototypeRegistryService) {
          return new PrototypeRegistryServiceProxy((PrototypeRegistryService) service, client, _sb);           
        }
        else if(service instanceof ThreadService) {
          return new ThreadServiceProxy((ThreadService) service, client, _sb); 
        }
        else if(service instanceof ThreadControlService) {
          return new ThreadControlServiceProxy((ThreadControlService) service, client, _sb); 
        }
        else if(service instanceof ThreadListenerService) {
          return new ThreadListenerServiceProxy((ThreadListenerService) service, client, _sb); 
        }
        return null;
      }
      
      protected  void releaseServiceProxy(Object serviceProxy, Object service, Class serviceClass) {
        if(serviceProxy instanceof SecureServiceProxy) {
          ((SecureServiceProxy)serviceProxy).releaseServices(); 
        }
        // else do nothing
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
          // set the jaas context here (not sure if we need to do this)
          final ServiceAvailableEvent fAe = ae;
          JaasClient jc = new JaasClient();
          jc.doAs(_ec, 
               new java.security.PrivilegedAction() {
                 public Object run() {
                    _sl.serviceAvailable(fAe);
                   return null;
                 }
               }, false);
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
          final ServiceRevokedEvent fRe = re;
          JaasClient jc = new JaasClient();
          jc.doAs(_ec, 
               new java.security.PrivilegedAction() {
                 public Object run() {
                   _sl.serviceRevoked(fRe);
                   return null;
                 }
               }, false);
          // reset the execution context for the current thread
          _scs.resetExecutionContext();
        }
      } // end SecurityServiceRevokedListener
    } // end PluginFilteringServiceBroker 
  } // end PluginServiceFilterBinder
} // end PluginServiceFilter
