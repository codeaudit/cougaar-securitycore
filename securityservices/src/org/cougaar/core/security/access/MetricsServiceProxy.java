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
import org.cougaar.core.qos.metrics.Metric;
import org.cougaar.core.qos.metrics.MetricNotificationQualifier;
import org.cougaar.core.qos.metrics.MetricsService;
import org.cougaar.core.qos.metrics.VariableEvaluator;
import org.cougaar.core.security.auth.ExecutionContext;

import java.util.Hashtable;
import java.util.Observable;
import java.util.Observer;
import java.util.Properties;

// this class is a proxy for the MetricsService
class MetricsServiceProxy extends SecureServiceProxy 
  implements MetricsService {
  private final MetricsService _ms;
  private final Object _requestor;
  private static Hashtable _observers = new Hashtable();
  
  public MetricsServiceProxy(MetricsService ms, Object requestor, ServiceBroker sb) {
    super(sb);
    _ms = ms;
    _requestor = requestor;
  }
  
  public Metric getValue(String path) {
    return _ms.getValue(path);  
  }
            
  public Metric getValue(String path, Properties qos_tags) {
    return _ms.getValue(path, qos_tags);
  }
   
  public Metric getValue(String path, VariableEvaluator evaluator) {
    return _ms.getValue(path, evaluator);
  }
            
  public Metric getValue(String path, VariableEvaluator evaluator, 
    Properties qos_tags) {
    return _ms.getValue(path, evaluator, qos_tags);
  }
            
  public Object subscribeToValue(String path, Observer observer) {
    return _ms.subscribeToValue(path, observer);
  }
           
  public Object subscribeToValue(String path, Observer observer, 
    MetricNotificationQualifier qualifier) {
    return _ms.subscribeToValue(path, observer, qualifier);
  }
                  
  public Object subscribeToValue(String path, Observer observer, 
    VariableEvaluator evaluator) {
    return _ms.subscribeToValue(path, observer, evaluator);
  }
            
  public Object subscribeToValue(String path, Observer observer, 
    VariableEvaluator evaluator, MetricNotificationQualifier qualifier) {
    return _ms.subscribeToValue(path, observer, evaluator, qualifier);
  }
         
  public void unsubscribeToValue(Object subscription_handle) {
    Object subscription = subscription_handle;
    if(subscription_handle instanceof Observer) {
      subscription = removeObserver((Observer)subscription_handle);
    }
    _ms.unsubscribeToValue(subscription);
  }
  
  private Observer addObserver(Observer o) {
    Observer so = new SecureObserver(o, _scs.getExecutionContext());
    _observers.put(o, so);
    return so; 
  }
  private Observer removeObserver(Observer o) {
    return (Observer)_observers.remove(o);
  }
  
  class SecureObserver implements Observer {
    Observer _o;
    ExecutionContext _ec;
    SecureObserver(Observer o, ExecutionContext ec) {
      _o = o;
      _ec = ec;
    }
    public void update(Observable o, Object obj) {
       _scs.setExecutionContext(_ec);
       _o.update(o, obj);
       _scs.resetExecutionContext();
    }
  }
}
