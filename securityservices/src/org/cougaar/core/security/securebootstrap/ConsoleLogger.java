
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

public class ConsoleLogger
  extends Logger
{
  public void debug(String s) {
    System.out.println("DEBUG:" + s);
  }
  public void debug(String s, Exception e) {
    System.out.println("DEBUG:" + s);
    e.printStackTrace();
  }

  public void info(String s) {
    System.out.println("INFO:" + s);
  }
  public void info(String s, Exception e) {
    System.out.println("INFO:" + s);
    e.printStackTrace();
  }

  public void warn(String s) {
    System.out.println("WARN:" + s);
  }
  public void warn(String s, Exception e) {
    System.out.println("WARN:" + s);
    e.printStackTrace();
  }

  public void error(String s) {
    System.out.println("ERROR:" + s);
  }
  public void error(String s, Exception e) {
    System.out.println("ERROR:" + s);
    e.printStackTrace();
  }

  public boolean isDebugEnabled() {
    return true;
  }
  public boolean isInfoEnabled() {
    return true;
  }
  public boolean isWarnEnabled() {
    return true;
  }
  public boolean isErrorEnabled() {
    return true;
  }
}
