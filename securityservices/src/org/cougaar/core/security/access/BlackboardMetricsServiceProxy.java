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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.service.BlackboardMetricsService;
import org.cougaar.util.UnaryPredicate;

// this class is a proxy for the BlackboardMetricsService
class BlackboardMetricsServiceProxy extends SecureServiceProxy 
  implements BlackboardMetricsService {
  private transient BlackboardMetricsService _bms;
  
  public BlackboardMetricsServiceProxy(BlackboardMetricsService bms, 
                                       Object requestor, ServiceBroker sb) {
    super(sb);
    _bms = bms;
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
    private transient Class _cl;
    ClassPredicate(Class cl) {
      _cl = cl;
    }
    public boolean execute(Object o) {
      return _cl.isAssignableFrom(o.getClass()); 
    }
  }
}
