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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.BlackboardMetricsService;
import org.cougaar.util.UnaryPredicate;

import org.cougaar.core.security.auth.ExecutionContext;

// this class is a proxy for the BlackboardMetricsService
class BlackboardMetricsServiceProxy extends SecureServiceProxy 
  implements BlackboardMetricsService {
  private BlackboardMetricsService _bms;
  private final Object _requestor;
  
  public BlackboardMetricsServiceProxy(BlackboardMetricsService bms, 
                                       Object requestor, ServiceBroker sb) {
    super(sb);
    _bms = bms;
    _requestor = requestor;
  }
  
  public int getBlackboardCount() {
    return _bms.getBlackboardCount();
  }
  public int getBlackboardCount(Class cl) {
    return getBlackboardCount(new ClassPredicate(cl));
  }
  public int getBlackboardCount(UnaryPredicate predicate) {
    ExecutionContext  ec = _scs.getExecutionContext();
    return _bms.getBlackboardCount(createSecurePredicate(predicate, ec));
  } 
   
  class ClassPredicate implements UnaryPredicate {
    Class _cl;
    ClassPredicate(Class cl) {
      _cl = cl;
    }
    public boolean execute(Object o) {
      return _cl.isAssignableFrom(o.getClass()); 
    }
  }
}
