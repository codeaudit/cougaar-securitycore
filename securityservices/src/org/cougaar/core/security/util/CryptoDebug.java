/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package org.cougaar.core.security.util;

// Cougaar security services
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.provider.SecurityServiceProvider;

public  class CryptoDebug {
  public static boolean debug =false;
  public static boolean crldebug =false;

  private static SecurityPropertiesService secprop = null;

  static {
    debug =
      (Boolean.valueOf(System.getProperty(SecurityPropertiesService.CRYPTO_DEBUG,
					   "false"))).booleanValue();
    crldebug =
      (Boolean.valueOf(System.getProperty(SecurityPropertiesService.CRYPTO_CRL_DEBUG,
					   "false"))).booleanValue();
  }

  public static void initContext(javax.servlet.Servlet servlet) {
    // TODO. Modify following line to use service broker instead
    secprop = SecurityServiceProvider.getSecurityProperties(servlet);

    debug =
      (Boolean.valueOf(secprop.getProperty(secprop.CRYPTO_DEBUG,
					   "false"))).booleanValue();
    crldebug =
      (Boolean.valueOf(secprop.getProperty(secprop.CRYPTO_CRL_DEBUG,
					   "false"))).booleanValue();
  }
} 
