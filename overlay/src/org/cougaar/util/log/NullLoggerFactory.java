/*
 * <copyright>
 *  Copyright 2001-2003 BBNT Solutions, LLC
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

import java.util.*;
import org.cougaar.util.*;

/** 
 * No-op LoggerFactory to connect to NullLogger instances.
 */
public class NullLoggerFactory 
  extends LoggerFactory 
{
  private static final LoggerController LC = new NullLoggerController();

  public void configure(Properties props) {}
  public void configure(Map m) {}
  public Logger createLogger(Object requestor) {
    return NullLogger.getLogger();
  }

  public LoggerController createLoggerController(String requestor) {
    return LC;
  }

  private static class NullLoggerController implements LoggerController {
    public LoggerController getLoggerController(String name) { return this; }
    public Enumeration getAllLoggerNames() { return new org.cougaar.util.EmptyEnumeration(); }
    public int getLoggingLevel() { return Logger.DEBUG; }
    public void setLoggingLevel(int level) {}
    public LogTarget[] getLogTargets() { return new LogTarget[0]; }
    public void addLogTarget(int outputType, Object outputDevice) {}
    public void addConsole() {}
    public boolean removeLogTarget(int outputType, Object outputDevice) {return false; }
    public boolean removeLogTarget( int outputType, String deviceString) {return false; }
  }
}
