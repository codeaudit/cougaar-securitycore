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

/** 
 * Static access to simple logging facilities.
 * <p>
 * Components may be better served by using the {@link org.cougaar.core.service.LoggingService LoggingService}
 */
public final class Logging 
{
  // cannot be instantiated
  private Logging() {}

  /** Alias for {@link LoggerFactory#getInstance()} **/
  public static LoggerFactory getLoggerFactory() {
    return LoggerFactory.getInstance();
  }

  /** The cache for getLogger() **/
  private static Map loggerCache = new WeakHashMap(11);

  /** Similar in function to <pre>
   *   LoggerFactory.getInstance().createLogger(name);
   * <pre>
   * except that this accessor memoizes the calls to 
   * reduce memory load.
   **/
  public static Logger getLogger(Object name) {
    synchronized (loggerCache) {
      String key = getKey(name);
      Logger l = (Logger) loggerCache.get(key);
      if (l == null) {
        l = LoggerFactory.getInstance().createLogger(name);
        // store the key as a new string instance to 
        // make sure it is collectable.
        loggerCache.put(new String(key), l);
      }
      return l;
    }
  }

  /** The cache for getLoggerController() **/
  private static Map lcCache = new WeakHashMap(11);

  /** Similar in function to <pre>
   *   LoggerFactory.getInstance().createLoggerController(name);
   * <pre>
   * except that this accessor memoizes the calls to 
   * reduce memory load.
   **/
  public static LoggerController getLoggerController(Object name) {
    synchronized (lcCache) {
      String key = getKey(name);
      LoggerController lc = (LoggerController) lcCache.get(key);
      if (lc == null) {
        lc = LoggerFactory.getInstance().createLoggerController(key);
        // store the key as a new string instance to 
        // make sure it is collectable.
        lcCache.put(new String(key), lc);
      }
      return lc;
    }
  }

  /** store for defaultLogger(), guarded by syncing on the class **/
  private static Logger defaultLogger = null;

  /** Returns the default Logger instance - the value returned by {@link #currentLogger()}
   * if there is no active context.
   **/
  public synchronized static Logger defaultLogger() {
    if (defaultLogger == null) {
      defaultLogger = getLogger("Default");
    }
    return defaultLogger;
  }

  /** Store for withLogger and currentLogger **/
  private static final ThreadLocal loggerContext = new ThreadLocal();


  /** Call a runnable in the dynamic context of a particular logger.
   * Anyone within that context can call {@link #currentLogger()}
   * to get access to an appropriate logger instance.
   * If no such instance has been installed, will use a generic 
   * logger with the name "Default".  This value may be retrieved
   * by calling {@link #defaultLogger()}.
   * @note withLogger may be called recursively, as the Logger contexts are
   * allowed to nest.
   * @note Child threads do not inherit Logger contexts.
   **/
  public static void withLogger(Logger l, Runnable r) {
    Logger old = (Logger) loggerContext.get();
    try {
      loggerContext.set(l);
      r.run();
    } finally {
      loggerContext.set(old);
    }
  }

  /** Return the Logger currently in-force in the current thread, as set
   * by {@link #withLogger(Logger,Runnable)}.
   * @return the current logger or the value returned by defaultLogger().  This method will
   * never return null.
   * @see #hasLogger()
   * @note Child threads do not inherit Logger contexts.
   **/
  public static Logger currentLogger() {
    Logger l = (Logger) loggerContext.get();
    if (l == null) {
      l = defaultLogger();
    }
    return l;
  }

  /** Is there a Logger in-force for the current thread?
   * @return true IFF currentLogger would return something other than the default logger.
   **/
  public static boolean hasLogger() {
    Logger l = (Logger) loggerContext.get();
    return (l != null);
  }

  //
  // private utilities
  // 

  /** Compute the Logging Name of the referenced object.
   * Used by various objects which can create Logger instances.
   **/
  public static final String getKey(Object x) {
    if (x instanceof Class) {
      return ((Class)x).getName();
    } else if (x instanceof String) {
      return (String) x;
    } else if (x == null) {
      return "null";
    } else {
      return x.getClass().getName();
    }
  }

}
