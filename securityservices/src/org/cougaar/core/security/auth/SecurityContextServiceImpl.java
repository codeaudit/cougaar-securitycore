/*
 * <copyright>
 *  Copyright 1997-2003 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 */
package org.cougaar.core.security.auth;

// core imports
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
// security services imports
import org.cougaar.core.security.auth.ExecutionPrincipal;
import org.cougaar.core.security.services.auth.SecurityContextService;
// java imports 
import java.lang.reflect.Method;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Iterator;
import javax.security.auth.Subject;

public final class SecurityContextServiceImpl 
  implements SecurityContextService {
    
  // the service broker 
  private ServiceBroker _serviceBroker;
  // logging service
  private LoggingService _log;
  // the client of this service
  private Object _requestor;
  // current mapping between an object and an security context
  private HashMap _currentSCMap = new HashMap();
  // previous mapping between an object and an security context
  private HashMap _previousSCMap = new HashMap();
  // logging flags  
  private boolean _debug = false;
  
  public SecurityContextServiceImpl(ServiceBroker sb) {
    _serviceBroker = sb;
    _log = (LoggingService)
      _serviceBroker.getService(this, LoggingService.class, null);
    _debug = _log.isDebugEnabled();
  }
  
  /**
   * Set the security context for the current thread.
   *
   * @param ec the security context to associate with the current thread
   */
  public void setExecutionContext(ExecutionContext ec) {
    setSecurityContext(ec, Thread.currentThread());
  }

  /**
   * Set the security context for a given object.
   *
   * @param oc the security context to associate with o
   * @param o object to associate the security context
   */
  public void setObjectContext(ObjectContext oc, Object o) {
    setSecurityContext(oc, o);
  }

  /**
   * Get the security context for the current thread.
   */
  public ExecutionContext getExecutionContext() {
    return (ExecutionContext)getSecurityContext(Thread.currentThread());
  }

  /**
   * Get the security context for the a given object.
   *
   * @param o an object
   */
  public ObjectContext getObjectContext(Object o) {
    return (ObjectContext)getSecurityContext(o);
  }
  /**
   * Reset the security context for the current thread to the previous security context.
   */
  public ExecutionContext resetExecutionContext() {
    return (ExecutionContext)resetSecurityContext(Thread.currentThread()); 
  }

  /**
   * Reset the security context for a given object to the previous security context.
   * 
   * @param o an object
   */
  public ObjectContext resetObjectContext(Object o) {
    return (ObjectContext)resetSecurityContext(o);
  }
  
  private ExecutionContext getExecutionContextFromJaas() {
    ExecutionContext ec = null;
    final AccessControlContext acc = AccessController.getContext();
    Subject subj = (Subject)
      AccessController.doPrivileged(new PrivilegedAction() {
        public Object run() {
          Subject subj = Subject.getSubject(acc);
          return subj;
        }
      });
    
    if (subj != null) {
      Iterator i = subj.getPrincipals().iterator();
      Principal p = null;
      while(i.hasNext()) {
        p = (Principal)i.next();
        if(p instanceof ExecutionPrincipal) {
          ExecutionPrincipal ep = (ExecutionPrincipal)p;
          ec = ep.getExecutionContext();
          return ec;
        }
      }
    }
    return null;
  }
  
  private void setSecurityContext(Object context, Object o) {
    Object oldContext = null;
    if(_debug) {
      _log.debug("setting security context for " + o);
      _log.debug("security context = " + context);
    }
    synchronized(_currentSCMap) {
      // associate the new security context with o,
      // and keep the old security context 
      oldContext = _currentSCMap.put(o, context);       
    }
    if(oldContext != null) {
      synchronized(_previousSCMap) {
        _previousSCMap.put(o, oldContext);
      }
      if(_debug) {
        _log.debug("preserving previous security context for " + o);
        _log.debug("previous security context " + oldContext);
      }
    }
  }
  
  private Object resetSecurityContext(Object o) {
    Object currentSC = null;
    Object oldSC = null;
    synchronized(_previousSCMap) {
       oldSC = _previousSCMap.get(o);
    }
    if(oldSC != null) {
      synchronized(_currentSCMap) {
        currentSC = _currentSCMap.put(o, oldSC);
      }
      if(_debug) {
        _log.debug("restoring security context for " + o);
        _log.debug("restored security context " + oldSC);
      }
    }
    else {
      synchronized(_currentSCMap) {
        currentSC = _currentSCMap.remove(o);
      }
    }
    if(_debug) {
        _log.debug("resetting security context for " + o);
        _log.debug("current security context = " + currentSC);
    }
    return currentSC;  
  }
  
  private Object getSecurityContext(Object o) {
    Object context = null;
    synchronized(_currentSCMap) {
      context = _currentSCMap.get(o);
      // don't know if we should do this?
      // if we don't, it means that we get a null context, and will deny all request
      if(context == null) {
        if(_debug) {
          _log.debug("no security context for " + o + ", getting JAAS context.");
        }
        context = getExecutionContextFromJaas();  // obtain context from Jaas
        /*
        if(context != null) {
          _currentSCMap.put(o, context); // associate the Jaas context with the object
        }
        */
        // return null if no ExecutionPrincipal in subject 
      }     
    }

    if(_debug) {
      _log.debug("getting security context for " + o + " = " + context);
    }
    return context; 
  }
}
