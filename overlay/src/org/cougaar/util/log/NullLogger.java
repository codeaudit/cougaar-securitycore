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

/** 
 * Logger where all "is*()" methods return false, and
 * all "log()" methods are ignored.
 *
 * @see Logger
 */
public class NullLogger 
  extends LoggerAdapter
{
  // singleton:
  private static final NullLogger NULL_LOGGER_SINGLETON = 
    new NullLogger();

  /** @deprecated old version of getLogger() **/
  public static NullLogger getNullLogger() {
    return NULL_LOGGER_SINGLETON;
  }

  /** Get the singleton instance of the NullLogger **/
  public static Logger getLogger() {
    return NULL_LOGGER_SINGLETON;
  }

  public boolean isEnabledFor(int level) {
    return false;
  }

  public void log(int level, String message, Throwable t) { }

  public String toString() {
    return "null-logger";
  }
}
