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

package org.cougaar.util.log.log4j;

import java.io.IOException;
import java.io.OutputStream;

import org.apache.log4j.Appender;
import org.apache.log4j.Priority;
import org.apache.log4j.Level;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.WriterAppender;
import org.apache.log4j.FileAppender;
import org.apache.log4j.SimpleLayout;

import org.cougaar.util.log.*;

/**
 * Package-private utility class for log4j utils.
 */
final class Util {

  private Util() {
    // just utility methods
  }

  // FIXME optimize to use "static final" arrays!!!
  // maybe alter the Logger constants to match log4j...

  /**
   * Private utility to change between int defined by Logger
   * and Priority class of log4j.
   * @param level An integer from Logger.
   * @deprecated Use Level methods instead
   */
  public static final Priority convertIntToPriority(int level) {
    switch (level) {
    case Logger.DETAIL: return DetailPriority.DETAIL;
    case Logger.DEBUG : return Priority.DEBUG;
    case Logger.INFO  : return Priority.INFO;
    case Logger.WARN  : return Priority.WARN;
    case Logger.ERROR : return Priority.ERROR;
    case Logger.SHOUT : return ShoutPriority.SHOUT;
    case Logger.FATAL : return Priority.FATAL;
    default: return null;
    }
  }

  /**
   * Private utility to change between int defined by Logger
   * and Priority class of log4j.
   * @param level A log4j Priority
   * @deprecated Use Level methods instead
   */
  public static final int convertPriorityToInt(Priority level) {
    switch (level.toInt()) {
      case DetailPriority.DETAIL_INT:return Logger.DETAIL;
      case Priority.DEBUG_INT:       return Logger.DEBUG;
      case Priority.INFO_INT :       return Logger.INFO;
      case Priority.WARN_INT :       return Logger.WARN;
      case Priority.ERROR_INT:       return Logger.ERROR;
      case ShoutPriority.SHOUT_INT:  return Logger.SHOUT;
      case Priority.FATAL_INT:       return Logger.FATAL;
      default:                       return 0;
    }
  }

  /**
   * Private utility to change between int defined by Logger
   * and Level class of log4j.
   * @param level An integer from Logger.
   */
  public static final Level convertIntToLevel(int level) {
    switch (level) {
    case Logger.DETAIL: return DetailPriority.DETAIL;
    case Logger.DEBUG : return Level.DEBUG;
    case Logger.INFO  : return Level.INFO;
    case Logger.WARN  : return Level.WARN;
    case Logger.ERROR : return Level.ERROR;
    case Logger.SHOUT : return ShoutPriority.SHOUT;
    case Logger.FATAL : return Level.FATAL;
    default: return null;
    }
  }

  /**
   * Private utility to change between int defined by Logger
   * and Level class of log4j.
   * @param level A log4j Level
   */
  public static final int convertLevelToInt(Level level) {
    switch (level.toInt()) {
      case DetailPriority.DETAIL_INT:return Logger.DETAIL;
      case Level.DEBUG_INT:          return Logger.DEBUG;
      case Level.INFO_INT:           return Logger.INFO;
      case Level.WARN_INT:           return Logger.WARN;
      case Level.ERROR_INT:          return Logger.ERROR;
      case ShoutPriority.SHOUT_INT:  return Logger.SHOUT;
      case Level.FATAL_INT:          return Logger.FATAL;
      default:                       return 0;
    }
  }

  /**
   * Helper function to convert the interfaces outputType (See 
   * {@link LogTarget}) into a log4j equivilent
   * Appender class.
   *
   * @param outputType - The input type CONSOLE, FILE, or STREAM
   * from {@link LogTarget.CONSOLE LogTarget}
   * @return The log 4j Appender class corresponding to the CONSOLE
   */
  public static Class convertIntToAppenderType(int outputType) {
    switch (outputType) {
      case LogTarget.CONSOLE:
        return ConsoleAppender.class;
      case LogTarget.STREAM:
        return WriterAppender.class;
      case LogTarget.FILE:
        return FileAppender.class;
      default:
        return null;
    }
  }

  /**
   * Helper function to convert outputType and device into the 
   * actual appropriate Appender, used for adding output types.
   *
   * @param outputType - The output type either CONSOLE, FILE, or 
   * STREAM of logging output to be removed. 
   * See {@link LogTarget}.
   * @param outputDevice - The device associated with the 
   * particular APPENDER.
   */
  public static Appender convertIntToAppender(
      int outputType, 
      Object outputDevice) {
    switch (outputType) {
      case LogTarget.CONSOLE: 
        return new ConsoleAppender(new SimpleLayout());
      case LogTarget.STREAM: 
        if ((outputDevice != null) && 
            (outputDevice instanceof OutputStream)) {
          WriterAppender appender = 
            new WriterAppender(
                new SimpleLayout(), 
                (OutputStream) outputDevice);
          appender.setName(Integer.toString(outputDevice.hashCode()));
        } else {
          //Report Error
        }
        break;
      case LogTarget.FILE: 
        if ((outputDevice != null) && 
            (outputDevice instanceof String)) {
          try {
            return new FileAppender(
                new SimpleLayout(), (String) outputDevice, true);
          } catch (IOException e) {
            //Report Error
          }
        } else {
          //Report Error
        }
        break;
      default:
        //Report Error
        return null;
    }
    return null;
  }
}
