/*
 * <copyright>
 *  Copyright 1997-2003 BBNT Solutions, LLC
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
 */

package org.cougaar.util.log;

import java.util.Enumeration;

/**
 * This class simply wraps a LoggerController and proxies it.
 *
 * @see LoggerController
 */
public class LoggerControllerProxy implements LoggerController {

  protected LoggerController lc;

  public LoggerControllerProxy(LoggerController lc) {
    this.lc = lc;
  }

  public LoggerController getLoggerController(String name) {
    return lc.getLoggerController(name);
  }
  public Enumeration getAllLoggerNames() {
    return lc.getAllLoggerNames();
  }
  public int getLoggingLevel() {
    return lc.getLoggingLevel();
  }
  public void setLoggingLevel(int level) {
    lc.setLoggingLevel(level);
  }
  public LogTarget[] getLogTargets() {
    return lc.getLogTargets();
  }
  public void addLogTarget(
      int outputType, Object outputDevice) {
    lc.addLogTarget(outputType, outputDevice);
  }
  public void addConsole(){
    lc.addConsole();
  }
  public boolean removeLogTarget(
      int outputType, Object outputDevice) {
    return lc.removeLogTarget(outputType, outputDevice);
  }
  public boolean removeLogTarget(
      int outputType, String deviceString){
    return lc.removeLogTarget(outputType, deviceString);
  }

  public String toString() {
    return lc.toString();
  }

}
