/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.policy.webproxy;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

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
  private String _ontologyFileName;
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
    String path = u.getPath();
    int index = path.lastIndexOf("/");
    String filename = path.substring(index + 1);
    if (_log != null && _log.isDebugEnabled()) {
      _log.debug("Retrieved file name = " + filename);
    }
    _ontologyFileName = "Ontology-" + filename;
  }


  /**
   * This function is called even if the user bypasses this step.  If
   * opens the Daml file as a stream.
   */
  public void connect() throws IOException
  {
    if (_log != null && _log.isDebugEnabled()) {
      _log.debug("Connecting...");
    }
    ConfigFinder cf = ConfigFinder.getInstance();
    _input = cf.open(_ontologyFileName);
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
