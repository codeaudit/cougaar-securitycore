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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

/**
 * This code is responsible for handling http connections.  It
 * supports daml files by reading them off of the cougaar config
 * files.  It supports HTTP by running the default HTTP stream handler
 * code.
 */
class DamlURLStreamHandler extends URLStreamHandler
{
  private static LoggingService _log = null;

  /**
   * Give this class a service broker so that it can start debugging.
   */
  static public void installServiceBroker(ServiceBroker sb)
  {
    _log = (LoggingService)
      sb.getService(new DamlURLStreamHandler(), LoggingService.class, null);
  }


  /**
   * This code selects either opens a connection using the regular web
   * client or using the daml client.
   */
  protected URLConnection openConnection(URL u)
    throws IOException
  {
    if (_log != null && _log.isDebugEnabled()) {
      _log.debug("Opening url " + u.toString());
    }
    if (u.toString().endsWith(".owl") && 
        u.toString().startsWith("http://ontology.ihmc.us")) {
      if (_log != null && _log.isDebugEnabled()) {
        _log.debug("Using proxy");
        _log.debug("++++++++++++++++++++++++++++++++++++++++++++++++");
      }
      return new DamlURLConnection(u);
    } else {
      /*
       * Otherwise go to Howard Street in San Francisco...
       */
      if (_log != null && _log.isDebugEnabled()) {
        _log.debug("Howard Street");
        _log.debug("Using original web client");
        _log.debug("++++++++++++++++++++++++++++++++++++++++++++++++");
      }
      return new sun.net.www.protocol.http.HttpURLConnection(u,
                                                             u.getHost(),
                                                             u.getPort());
    }
  }
}
