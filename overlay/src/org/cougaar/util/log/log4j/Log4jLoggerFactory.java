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

import java.util.*;
import java.net.URL;
import org.apache.log4j.xml.DOMConfigurator;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.PropertyConfigurator;


import org.cougaar.util.log.*;
import org.cougaar.util.*;

import java.io.InputStream;
import java.io.IOException;

import org.cougaar.bootstrap.SystemProperties;

/** 
 * Log4j implementation of LoggerFactory, which is used to
 * create Logger and LoggerController instances.
 * <p>
 * Typically the "requestor" classname is used to identify 
 * loggers.  A special "name" is "root", which is used
 * to specify the root (no-parent) logger.
 * The properties may specify a name which it interpreted as a URL
 * according to the definition of org.cougaar.util.ConfigFinder.canonicalizeElement
 * In particular, it may be a URL or filename with embedded ConfigFinder directives.
 * In addition, if there are no path separators in config specified, it will 
 * interpret it as a filename in COUGAAR_INSTALL_PATH/configs/common.
 * The config files may be either in log4j XML format (ending with .xml) or
 * log4j properties format (ending in .props or .properties).
 * @property org.cougaar.util.log.config Specifies a URL where a LoggerFactory configuration
 * file may be found.  The Log4jLoggerFactory inteprets this as a file of log4j properties, overridable
 * by org.cougaar.logging.* properties.
 * @property org.cougaar.core.logging.config.filename
 * Alias for the property "org.cougaar.util.log.LoggerFactory.config"
 * Load logging properties from the named file, which is
 * found using the ConfigFinder.  Currently uses log4j-style
 * properties; see
 * <a href="http://jakarta.apache.org/log4j/docs/manual.html">the log4j manual</a>
 * for valid file contents.
 * @property org.cougaar.core.logging.*
 *    Non-"config.filename" properties are stripped of their 
 *    "org.cougaar.core.logging." prefix and passed to the
 *    logger configuration.  These properties override any 
 *    properties defined in the (optional) 
 *    "org.cougaar.core.logging.config.filename=STRING" 
 *    property.
 */
public class Log4jLoggerFactory 
  extends LoggerFactory 
{
  public static final String PREFIX = "org.cougaar.core.logging.";
  public static final String FILE_NAME_PROPERTY = PREFIX + "config.filename";
  public static final String LOG4JCONF = "log4j.configuration";

  /**
   * Default configuration only prints WARN or higher
   * statements.
   * <p>
   * A client with name "x.y.z" that calls:<pre>
   *   log.warn("test message");
   * </pre>
   * will generate a standard-output message similar to:</pre>
   *   2002-03-08 22:26:08,980 WARN [z] - test message
   * </pre>.
   * <p>
   * See the log4j docs for further details.
   */
  private static final String[][] DEFAULT_PROPS = {
    {"log4j.rootCategory",                            "WARN,A1" },
    {"log4j.appender.A1",                             "org.apache.log4j.ConsoleAppender" },
    {"log4j.appender.A1.layout",                      "org.apache.log4j.PatternLayout" },
    {"log4j.appender.A1.layout.ConversionPattern",    "%d{ISO8601} %-5p [%c{1}] - %m%n" },
  };

  private static final Properties DEFAULT_PROPERTIES;

  static {
      Properties p = new Properties();
      for (int i = 0, n = DEFAULT_PROPS.length; i < n; i++) {
        p.put(DEFAULT_PROPS[i][0], DEFAULT_PROPS[i][1]);
      }
      DEFAULT_PROPERTIES = p;
  }


  public Log4jLoggerFactory() {
    Throwable err = null;    // post the error after the fact if we need to

    String name;
    name = System.getProperty(LF_CONFIG_PROP);
    if (name == null) {
      name = System.getProperty(FILE_NAME_PROPERTY);
    }
    if (name == null) {
      name = System.getProperty(LOG4JCONF);
    }

    try {
      if (name != null) {
        if (name.indexOf("/")==-1) {
          name = "$INSTALL/configs/common/"+name;
        }
        URL cu = Configuration.canonicalizeElement(name);
        if (cu != null) {
          String s = cu.getFile();
          if (s.endsWith(".xml")) {
            DOMConfigurator.configure(cu);
          } else {
            PropertyConfigurator.configure(cu);
          }
          org.apache.log4j.Logger.getLogger(Log4jLoggerFactory.class).info("Configured logging from "+cu);
          configureFromSystemProperties();
          return;
        } else {
          err = new RuntimeException("Could not resolve "+name+" to a URL.");
        }
      } 
    } catch (Exception e) {
      err = e;
    }

    // if all else fails, we'll fall through to:
    try {
      PropertyConfigurator.configure(DEFAULT_PROPERTIES);
    } catch (Exception e) {
      BasicConfigurator.configure();
      org.apache.log4j.Logger.getLogger(Log4jLoggerFactory.class).error("Failed default log4j initialization", e);
    }      

    if (err != null) {
      org.apache.log4j.Logger.getLogger(Log4jLoggerFactory.class).error("Failed standard log4j initialization", err);
    }
    configureFromSystemProperties();
  }

  private void configureFromSystemProperties() {
    Properties props = SystemProperties.getSystemPropertiesWithPrefix(PREFIX);
    Properties cp = new Properties();

    for (Iterator it = props.keySet().iterator(); it.hasNext(); ) {
      String name = (String) it.next();
      if (name.equals(FILE_NAME_PROPERTY)) {
        continue;
      }

      String value = props.getProperty(name);
      name = name.substring(PREFIX.length());
      cp.put(name, value);
    }
    PropertyConfigurator.configure(cp);
    org.apache.log4j.Logger.getLogger(Log4jLoggerFactory.class).info("Configured logging from "+cp.size()+" System Properties");
  }

  // ugh. bashing of static structure... sigh.
  public void configure(Properties props) {
    PropertyConfigurator.configure(props);
  }
  // ugh. bashing of static structure... sigh.
  public void configure(Map m) {
    Properties p = new Properties();
    p.putAll(m);
    PropertyConfigurator.configure(p);
  }

  public Logger createLogger(Object requestor) {
    return new LoggerImpl(requestor);
  }

  public LoggerController createLoggerController(String requestor) {
    (new Throwable()).printStackTrace();
    return new LoggerControllerImpl(requestor);
  }
}
