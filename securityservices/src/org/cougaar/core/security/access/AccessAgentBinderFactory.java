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

import org.cougaar.core.component.ServiceFilter;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class AccessAgentBinderFactory extends ServiceFilter
{
  private static Logger _log;
 
  static {
    _log = LoggerFactory.getInstance().createLogger(AccessAgentBinderFactory.class);
    if (_log.isDebugEnabled()) {
      _log.debug("Loading " + AccessAgentBinderFactory.class.getName());
    }
  }

  public AccessAgentBinderFactory() {
    super();
    if (_log.isDebugEnabled()) {
      _log.debug("Constructing " + getClass().getName());
    }
  }
 
  protected Class getBinderClass(Object child) {
    if (_log.isDebugEnabled()) {
      _log.debug("getBinderClass: " + child.getClass().getName());
    }
    return AccessAgentBinder.class;
  }
  
  public void setParameter(Object o) {
    if (_log.isDebugEnabled()) {
      _log.debug("setParameter: " + o);
    }
  }
  
  public int getPriority() {
    return NORM_PRIORITY; 
  }
}

