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

import java.io.Serializable;

/**
 * Represents an output destination of a named logger.
 * <p>
 * Note that a single Logger instance can have multiple
 * LogTargets.
 */
public class LogTarget implements Serializable {

  /**
   * Generic target type identifiers.
   * <p>
   * The value of these constants may be modified in the future
   * without notice.  For example, "CONSOLE" may be changed from
   * "1" to "0".
   */
  public static final int CONSOLE = 1;
  public static final int STREAM  = 2;
  public static final int FILE    = 3;

  private final String name;
  private final int    outputType;
  private final String outputDevice;
  private final int    loggingLevel;

  public LogTarget(
      String name,
      int    outputType,
      String outputDevice,
      int    loggingLevel) {
    this.name = name;
    this.outputType = outputType;
    this.outputDevice = outputDevice;
    this.loggingLevel = loggingLevel;
  }

  /**
   * @return The name for this logger
   */
  public String getName() {
    return name;
  }

  /**
   * @return a constant (CONSOLE, STREAM, or FILE)
   */
  public int getOutputType() {
    return outputType;
  }

  /**
   * @return The device identifier (null for CONSOLE, filename for FILE,
   *         and stream-id for STREAM)
   */
  public String getOutputDevice() {
    return outputDevice;
  }

  /**
   * @return a Logger constant for the logger's level (DEBUG, etc)
   */
  public int getLoggingLevel() {
    return loggingLevel;
  }

  public String toString() {
    return "logger \""+name+"\"";
  }
}
