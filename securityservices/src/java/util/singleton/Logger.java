/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

public class Logger
{
  private static Logger _logger;

  public void debug(String s) {
  }
  public void debug(String s, Exception e) {
  }
  public void info(String s) {
  }
  public void info(String s, Exception e) {
  }
  public void warn(String s) {
  }
  public void warn(String s, Exception e) {
  }
  public void error(String s) {
  }
  public void error(String s, Exception e) {
  }

  public boolean isDebugEnabled() {
    return false;
  }
  public boolean isInfoEnabled() {
    return false;
  }
  public boolean isWarnEnabled() {
    return false;
  }
  public boolean isErrorEnabled() {
    return false;
  }

  public static Logger getInstance() {
    if (_logger == null) {
      try {
	_logger = (Logger)
	  Class.forName
	  (System.getProperty
	   ("org.cougaar.core.security.securebootstrap.logger")).newInstance();
      }
      catch (Exception e) {
	_logger = new NullLogger();
      }
    }
    return _logger;
  }
}
