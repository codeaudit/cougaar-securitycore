/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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

package org.cougaar.core.security.policy.webproxy;

import java.io.PrintStream;

import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;

import org.cougaar.core.security.policy.webproxy.DamlURLStreamHandler;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;


/**
 * This is a factory that takes a protocol and generates a
 * URLStreamHandler.  
 *
 * The URLStreamHandler then takes a URL and returns a
 * URLStreamHandler.  The URLStreamHandler is an object that knows how
 * to make a connection for a paticular protocol type (e.g. ftp, http,
 * jar, jndi). This factory constructs URLStreamHandlers for the http
 * and jndi protocols.  Documentation of the place of this factory in
 * the lifecycle of a URL can be found in the javadocs for the
 *
 *     URL(String protocol,
 *         String host,
 *         int port,
 *         String file)
 *
 * constructor.  
 */
class DamlURLStreamHandlerFactory implements URLStreamHandlerFactory
{
  static private LoggingService _log = null;

  /**
   * Give this class a service broker so that it can start debugging.
   */
  static public void installServiceBroker(ServiceBroker sb)
  {
    _log = (LoggingService)
      sb.getService(new DamlURLStreamHandlerFactory(), 
                    LoggingService.class, null);
  }

  /**
   * This method provides URLStreamHandlers for the jndi and http
   * protoocols.
   *
   * The http handler is here so that daml pages can be loaded
   * directly from the cougaar config files rather than off the
   * network.
   *
   * The jndi handler is here for support of the tomcat engine.  This
   * webproxy prevents tomcat from loading its own jndi protocol
   * support so we must implement it here.  This needs testing - I did
   * the obvious thing but it is a little different than what tomcat
   * does. 
   */

  public URLStreamHandler createURLStreamHandler(String protocol) {
    if (_log != null && _log.isDebugEnabled()) {
      _log.debug("+++++++++++++++++++++++++++++++++++++++++++++++++");
      _log.debug("Protocol = " + protocol);
    }
    if (protocol.equals("http")) {
      if (_log != null && _log.isDebugEnabled()) {
        _log.debug("Returning the proxy handler");
      }
      return new DamlURLStreamHandler();
    } else if (protocol.equals("jndi")) {
      return new org.apache.naming.resources.DirContextURLStreamHandler();
    } else {
      if (_log != null && _log.isDebugEnabled()) {
        _log.debug("using the default handler");
      }
      return null;
    }
  }

}
