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
 * A controller for a single Logger, used to set the logging levels 
 * and output destinations (console, files, etc).
 * <p>
 * This API is a bit kludgy -- it needs to be refactored into
 * a more "readable" API, including a refactoring of 
 * LogTarget. For now I'm more concerned with the Logger 
 * API, since it will be used by all developers, than this 
 * LoggerController API.
 */
public interface LoggerController {

  /**
   * Special "static" method to get a named logger-controller.
   * <p>
   * This should be moved to a different interface...
   */
  LoggerController getLoggerController(String name);

  /**
   * Special "static" method to get the names of all loggers.
   * <p>
   * This should be moved to a different interface...
   */
  Enumeration getAllLoggerNames();

  /**
   * Get the logging level.
   *
   * @return a Logger level constant (DEBUG, INFO, etc)
   *
   * @see Logger
   */
  int getLoggingLevel();

  /**
   * Set the logging level.
   *
   * @param a Logger level constant (DEBUG, INFO, etc)
   *
   * @see Logger
   */
  void setLoggingLevel(int level);

  /**
   * Get an array of all LogTargets for this logger.
   *
   * return an array of {@link LogTarget} representing all
   * the various logging destinations.
   */
  LogTarget[] getLogTargets();

  /**
   * Add a logging destination.
   *
   * @param outputType The LogTarget constant (CONSOLE, FILE, or STREAM).
   * @param outputDevice The device associated with the particular output
   * type being added.  Null for Console, filename for FILE, the actual
   * output stream object for STREAM.
   *
   */
  void addLogTarget(
      int outputType, Object outputDevice);

  /**
   * Add a console output type to this logger.
   * <p>
   * This is equivalent to:<pre/>
   *   addLogTarget(LogTarget.CONSOLE, null);</pre>
   */
  void addConsole();

  /**
   * Remove a logging output type.
   *
   * @param outputType The LogTarget constant (CONSOLE, FILE, or STREAM) of
   * logging output to be removed. See constants above.
   * @param outputDevice The device associated with the particular output
   * type being removed.  Null for Console, filename for FILE, the actual
   * output stream object for STREAM.
   */
  boolean removeLogTarget(
      int outputType, Object outputDevice);

  /**
   * Remove a logging output type.
   * 
   * This method is usually used in conjunction with 
   * {@link #getLogTargets()} to
   * iterate through list to remove items.
   *
   * @param outputType The LogTarget constant (CONSOLE, FILE, or STREAM) of
   * logging output to be removed. See constants above.
   * @param deviceString - The device associated with the particular output
   * type being removed.  Null for Console, filename for FILE,
   * the String identifier name associated with the output stream.
   */
  boolean removeLogTarget(
      int outputType, String deviceString);

}
