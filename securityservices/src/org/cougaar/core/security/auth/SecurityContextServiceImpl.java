/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
 
 
 
 
 
 

package org.cougaar.core.security.auth;

// core imports
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.EmptyStackException;
import java.util.Iterator;
import java.util.Stack;
import java.util.WeakHashMap;

import javax.security.auth.Subject;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.auth.SecurityContextService;
import org.cougaar.core.service.LoggingService;

public final class SecurityContextServiceImpl 
  implements SecurityContextService {
    
  // the service broker 
  private ServiceBroker _serviceBroker;
  // logging service
  private LoggingService _log;
  // the client of this service
  //private Object _requestor;
  // current mapping between an object and an security context stack
  private WeakHashMap _contextMap = new WeakHashMap();
  
  public SecurityContextServiceImpl(ServiceBroker sb) {
    _serviceBroker = sb;
    _log = (LoggingService)
      _serviceBroker.getService(this, LoggingService.class, null);
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

  // IMPLEMENTATION USING STACK TO TRACK ALL EXECUTION CONTEXT
  private void setSecurityContext(Object context, Object o) {
    synchronized(_contextMap) {
      // associate the new security context with o,
      // and keep the old security context 
      Stack es = (Stack)_contextMap.get(o);
      if(es == null) {
        if(_log.isDebugEnabled()) {
          _log.debug("creating stack for " + o);
        }
        es = new Stack();
        _contextMap.put(o, es); 
      }
      es.push(context);
      if(_log.isDebugEnabled()) {
        _log.debug("pushed (" + o + ", " + context + ") onto stack"); 
        _log.debug("stack size: " + es.size());
      }
    }
  }
  private Object resetSecurityContext(Object o) {
    Object context = null;
    synchronized(_contextMap) {
      Stack es = (Stack)_contextMap.get(o);
      if(es != null) {
        try {
          context = (ExecutionContext)es.pop();
          if(_log.isDebugEnabled()) {
            _log.debug("reset security context for: " +  o);
            _log.debug("stack size: " +  es.size());
          }
        }
        catch(EmptyStackException ese) {
          _log.warn("execution stack is empty for: " + o);
        }
      }
    }
    return context;  
  }
  
  private Object getSecurityContext(Object o) {
    Object context = null;
    synchronized(_contextMap) {
      Stack es = (Stack)_contextMap.get(o);
      try {
        if(es != null) {
          context = es.peek(); 
        }
      }
      catch(EmptyStackException ese) {
        if(_log.isDebugEnabled()) {
          _log.debug("execution stack is empty for: " + o);
        }
      }
    }
    // don't know if we should do this?
    // if we don't, it means that we get a null context, and will deny all request
    if(context == null) {
      if(_log.isDebugEnabled()) {
        _log.debug("no security context for " + o + ", getting JAAS context.");
      }
      context = getExecutionContextFromJaas();  // obtain context from Jaas
      // return null if no ExecutionPrincipal in subject 
    }     
   
    if(_log.isDebugEnabled()) {
      _log.debug("got security context (" + o + ", " + context + ")");
    }
    return context; 
  }
}
