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

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;

import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.ConfigFinder;

/**
 * This class provides access to daml files as a file stream rather
 * than as a connection to web server as they would normally be
 * provided.  If this class can't find the ontology file then this
 * class returns an IOException.
 */
public class DamlURLConnection extends URLConnection
{
  static private LoggingService _log = null;
  private File _damlFile;
  private InputStream _input;
  private boolean _connected = false;

  /**
   * Give this class a service broker so that it can start debugging.
   */
  static public void installServiceBroker(ServiceBroker sb)
  {
    _log = (LoggingService)
      sb.getService(new DamlURLConnection(), LoggingService.class, null);
  }

  private DamlURLConnection() {
    super(null);
  }

  /**
   * Initialize the URLConnection based on the URL.
   *
   * Don't check for errors (e.g. file not found) yet as they will get
   * throws when the user attempts to connect.
   */
  public DamlURLConnection(URL u) {
    super(u);
    if (_log != null && _log.isDebugEnabled()) {
      _log.debug("URL = " + u);
    }
    ConfigFinder cf = ConfigFinder.getInstance();
    String path = u.getPath();
    int index = path.lastIndexOf("/");
    String filename = path.substring(index + 1);
    if (_log != null && _log.isDebugEnabled()) {
      _log.debug("Retrieved file name = " + filename);
    }
    _damlFile = cf.locateFile("Ontology-" + filename);
  }


  /**
   * This function is called even if the user bypasses this step.  If
   * opens the Daml file as a stream.
   */
  public void connect() throws IOException
  {
    if (_damlFile == null) {
      throw new IOException("File not found - probably ConfigFinder problem...");
    }
    if (_log != null && _log.isDebugEnabled()) {
      _log.debug("Connecting...");
    }
    _input = new FileInputStream(_damlFile);
    _connected = true;
  }

  /**
   * Provides the open file stream to the requesting user.
   */
  public InputStream getInputStream() throws IOException
  {
    if (_log != null && _log.isDebugEnabled()) {
      _log.debug("getting input stream");
    }
    if (!_connected) {
      connect();
    }
    return _input;
  }
}
