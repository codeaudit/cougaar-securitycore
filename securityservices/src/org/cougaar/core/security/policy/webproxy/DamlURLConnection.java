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
    _damlFile = cf.locateFile(filename);
  }

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
