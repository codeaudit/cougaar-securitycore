/*
 * <copyright>
 *  Copyright 1997-2001 Cougaar Software, Inc.
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
 * CHANGE RECORD
 * - 
 */

package org.cougaar.core.security.securebootstrap;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

/**
 * An invocation handler that passes on any calls made to it
 * directly to its delegate. This is useful to handle identical
 * classes loaded in different classloaders - the VM treats them
 * as different classes, but they have identical signatures.
 * <p>
 * Note this is using class.getMethod, which will only work on public methods.
 */
class PassThroughProxyHandler
  implements InvocationHandler {
  private final Object delegate;
  public PassThroughProxyHandler(Object delegate) {
    this.delegate = delegate;
  }
  public Object invoke(Object proxy, Method method, Object[] args)
    throws Throwable {
    Method delegateMethod = delegate.getClass().getMethod
      (method.getName(), method.getParameterTypes());
    return delegateMethod.invoke(delegate, args);
  }
}
