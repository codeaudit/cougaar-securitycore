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

package org.cougaar.core.security.pedigree;

// core classes
import org.cougaar.core.component.ServiceFilter;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class ServiceBrokerFilterBinderFactory extends ServiceFilter {
  private static Logger _log;

  static {
    _log = LoggerFactory.getInstance().createLogger(ServiceBrokerFilterBinderFactory.class);
  }

  public ServiceBrokerFilterBinderFactory() {
    if (_log.isDebugEnabled()) {
      _log.debug("Instantiating binder factory: " + this);
    }
  }

  //  This method specifies the Binder to use (defined later)
  protected Class getBinderClass(Object child) {
    return ServiceBrokerFilterBinder.class;
  }
  
  //this is here as a patch
  public void setParameter(Object o) {}

  public int getPriority() { return NORM_PRIORITY; }
  
} // end LogicProviderBinderFactory
