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

public class SecurityPropertiesServiceImpl
  implements SecurityPropertiesService
{
  private javax.servlet.ServletContext servletContext = null;

  public SecurityPropertiesServiceImpl() {
  }

  public SecurityPropertiesServiceImpl(javax.servlet.ServletContext aServletContext) {
    servletContext = aServletContext;
  }

  public String getProperty(String property) {
    return getProperty(property, null);
  }

  public String getProperty(String property, String defaultValue) {
    String value = null;
    if (servletContext != null) {
      value = (String) servletContext.getAttribute(property);
      if (value == null) {
	if (CryptoDebug.debug) {
	  System.out.println("WARNING: servlet attribute undefined: " + property
	    + ". Using system property");
	}
      }
    }
    if (value == null) {
      value = System.getProperty(property, defaultValue);
    }
    if (CryptoDebug.debug) {
      System.out.println("getProperty(" + property + ")=" + value);
    }
    return value;
  }

  public void setProperty(String property, String value) {
    if (CryptoDebug.debug) {
      System.out.println("setProperty(" + property + ")=" + value);
    }
    if (servletContext != null) {
      servletContext.setAttribute(property, value);
    }
    else {
      System.setProperty(property, value);
    }
  }
}
