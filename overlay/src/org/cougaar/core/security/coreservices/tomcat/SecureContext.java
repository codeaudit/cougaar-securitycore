/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 * Created on September 12, 2001, 10:55 AM
 */

package org.cougaar.core.security.coreservices.tomcat;

import java.lang.reflect.Method;

import org.apache.catalina.Context;
import org.apache.catalina.Valve;
import org.apache.catalina.core.StandardContext;

/**
 * A Tomcat Context which will inform the security services
 * of its creation if the security services exist and the
 * System property
 * <code>org.cougaar.core.security.coreservices.tomcat.disableAuth</code> 
 * is not "true".
 */
public class SecureContext extends StandardContext {

  private static final String PROP_DISABLE =
    "org.cougaar.core.security.coreservices.tomcat.disableAuth";
  private static final String SPP_CLASS  = 
    "org.cougaar.core.security.provider.ServletPolicyServiceProvider";

  private Method _sppSetDualAuthenticator = null;

  public SecureContext() {
    if (!Boolean.getBoolean(PROP_DISABLE)) {
      try {
        Class c  = Class.forName(SPP_CLASS);
        Method m = c.getMethod("setContext", new Class[] { Context.class });
        m.invoke(null, new Object[] { this });
      } catch (ClassNotFoundException e) {
        // don't worry about it
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
    
  }

}
