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

// cougaar core
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.DynamicUnaryPredicate;
import org.cougaar.glm.ldm.oplan.OrgActivity;

// security services
import org.cougaar.core.security.auth.BlackboardPermission;
import org.cougaar.core.security.auth.SecuredObject;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.role.RoleExecutionContext;
import org.cougaar.core.security.access.bbo.SecuredOrgActivity;
import org.cougaar.core.security.services.auth.SecurityContextService;

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
    _scs = (SecurityContextService)
      sb.getService(this, SecurityContextService.class, null);
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
              _log.warn("QUERY DENIED: [" + comp + ", " + object + "]");
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
