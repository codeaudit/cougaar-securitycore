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
 
package org.cougaar.core.security.access;

import java.security.PrivilegedAction;
import java.security.AccessController;
// cougaar core
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.access.bbo.SecuredOrgActivity;
import org.cougaar.core.security.auth.BlackboardPermission;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.SecuredObject;
import org.cougaar.core.security.auth.role.RoleExecutionContext;
import org.cougaar.core.security.services.auth.SecurityContextService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.util.DynamicUnaryPredicate;
import org.cougaar.util.UnaryPredicate;

// service proxies will need to extend this class to provide a way to 
// release the services that are required by the service proxy
class SecureServiceProxy {
  ServiceBroker _sb;
  SecurityContextService _scs;
  LoggingService _log;
  //Object _requestor;
  
  public static final String EFFICIENT_PROPERTY = 
    "org.cougaar.core.security.access.efficientBBS";
  // WARNING: This should only be set for debugging purposes.
  // If set to true, the unary predicate will be invoked to determine
  // if a warning should be logged to notify logistic plugin developers
  // that they do not have query access to SecuredObjects.
  public static final String DEBUG_AUTH_PROPERTY = 
    "org.cougaar.core.security.auth.debug";
  public static final boolean EFFICIENT = 
    Boolean.valueOf(System.getProperty(EFFICIENT_PROPERTY, "true")).booleanValue();
  public static final boolean AUTH_DEBUG = 
    Boolean.valueOf(System.getProperty(DEBUG_AUTH_PROPERTY, "false")).booleanValue();

  SecureServiceProxy(ServiceBroker sb) {//, Object requestor) {
    _sb = sb;
    AccessController.doPrivileged(new PrivilegedAction() {
      public Object run() {
        _scs = (SecurityContextService)
            _sb.getService(this, SecurityContextService.class, null);
        return null;
      }
    });
    _log = (LoggingService)
      sb.getService(this, LoggingService.class, null);  
//    _requestor = requestor;
  }
  // this method can be overwritten, but please ensure that super.releaseServices()
  // is called
  void releaseServices() {
    _sb.releaseService(this, SecurityContextService.class, _scs);
    _sb.releaseService(this, LoggingService.class, _log);
  }
  
  String getClassName(Object o) {
    if (o instanceof OrgActivity) {
      return OrgActivity.class.getName();
    }
    return o.getClass().getName();
  }

  boolean isValidClass(Object o) {
    return (o instanceof SecuredOrgActivity);
  }

  private boolean allowQuery(Object o, ExecutionContext ec, UnaryPredicate up) {
    if (EFFICIENT && !(o instanceof SecuredObject)) {
      return true;
    }
    SecurityManager sm = System.getSecurityManager();
    if(sm != null) {
      String object = getClassName(o);
      String comp = "unknown";      
      if(ec instanceof RoleExecutionContext) {
        comp = ((RoleExecutionContext)ec).getComponent();
      }
      try {
        if(_log.isDebugEnabled()) {
          _log.debug("checking query permission: [" + comp + ", " + object + "]");
        }
        _scs.setExecutionContext(ec);
        BlackboardPermission bbp = new BlackboardPermission(object, "query");
        sm.checkPermission(bbp);
        _scs.resetExecutionContext();
      }
      catch(SecurityException se) {
        // log this security exception as a warning ONLY IF 
        // org.cougaar.core.security.auth.debug is enabled
        if(AUTH_DEBUG) {
          if(up != null) {
            if(up.execute(o)) {
              _log.warn("QUERY DENIED: [" + comp + ", " + object + ", " + up + "]");
            }
          }
        }
        return false; 
      }
    }
    return true;
  }
 
  protected UnaryPredicate createSecurePredicate(UnaryPredicate up, ExecutionContext ec) {
    UnaryPredicate sup = null;
    if(up instanceof DynamicUnaryPredicate) {
      sup = new SecureDynamicUnaryPredicate((DynamicUnaryPredicate)up, ec); 
    }
    else {
      sup = new SecureUnaryPredicate(up, ec);
    }
    return sup;
  } 

  protected class SecureUnaryPredicate implements UnaryPredicate {
    private UnaryPredicate _up;
    private ExecutionContext _ec;
    SecureUnaryPredicate(UnaryPredicate up, ExecutionContext ec) {
      _up = up;
      _ec = ec;
    }
    public boolean execute(Object o) {
      if(!allowQuery(o, _ec, _up)) {
        // unauthorized access of protected objects
        return false;
      }
      // if _up is null that means that i'm only doing an authorization check.
      // at this point, authorization succeeded.
      return (_up != null ? _up.execute(o) : true);
    } 
  }
  
  protected class SecureDynamicUnaryPredicate extends SecureUnaryPredicate
    implements DynamicUnaryPredicate {
    SecureDynamicUnaryPredicate(DynamicUnaryPredicate dup, ExecutionContext ec) {
      super(dup, ec);
    }
  }
}
