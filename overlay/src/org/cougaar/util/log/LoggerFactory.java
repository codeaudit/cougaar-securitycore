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

import java.util.Map;
import java.util.Properties;

/** 
 * Factory to create Logger and LoggerController instances.
 * <p>
 * Typically the "requestor" classname is used to identify 
 * loggers.  A special "name" is "root", which is used
 * to specify the root (no-parent) logger.
 *
 * @property org.cougaar.util.log.LoggerFactory Specifies the LoggerFactory implementation class to instantiate
 * for use as the singleton logger.  The default value is "org.cougaar.util.log.log4j.Log4jLoggerFactory".  If
 * the specified factory cannot be found and initialized, an error message will be printed, and it will use
 * an instance of {@link NullLoggerFactory} instead.
 * @property org.cougaar.util.log.config Specifies a URL where a LoggerFactory configuration
 * file may be found.  The interpretation of this file (including ignoring it) is up to the implementation
 * class, but implementations are encouraged to use it.
 * 
 * @see org.cougaar.util.log.log4j.Log4jLoggerFactory
 * @see NullLoggerFactory
 */
public abstract class LoggerFactory {
  public static final String LF_PREFIX ="org.cougaar.util.log"; 
  public static final String LF_PROP = LF_PREFIX+".LoggerFactory";
  public static final String LF_CONFIG_PROP = LF_PREFIX+".config";
  public static final String LF_DEFAULT_CLASS = "org.cougaar.util.log.log4j.Log4jLoggerFactory";

  private static LoggerFactory singleton = null;

  public synchronized static final LoggerFactory getInstance() {
    if (singleton == null) {
      singleton = makeInstance();
    }
    return singleton;
  }

  private static final LoggerFactory makeInstance() {
    String lfname = System.getProperty(LF_PROP, LF_DEFAULT_CLASS);
    try {
      Class clazz = Class.forName(lfname);
      return (LoggerFactory) clazz.newInstance();
    } catch (Exception e) {
      System.err.println("Could not enable LoggerFactory \""+lfname+"\": will use NullLoggerFactory instead");
      e.printStackTrace();
      return new NullLoggerFactory();
    }
  }


  /** Implementations may override to provide 
   * additional configuration information to the underlying logging facility.
   * The default implementation does nothing.
   **/
  public void configure(Properties props) {
    getInstance().createLogger(LoggerFactory.class).error("Clients may not configure Loggers", new Throwable());
  }
  /** Implementations may override to provide 
   * additional configuration information to the underlying logging facility.
   * The default implementation does nothing.
   **/
  public void configure(Map m) {
    getInstance().createLogger(LoggerFactory.class).error("Clients may not configure Loggers", new Throwable());
  }

  /** Create a logger as named by the parameter.
   * If requestor is a Class, will use the class name.  If it is a String, it will
   * use it directly.  Anything else will use the name of the class that the 
   * object is an instance of.
   **/
  public abstract Logger createLogger(Object requestor);

  public abstract LoggerController createLoggerController(String requestor);
}
