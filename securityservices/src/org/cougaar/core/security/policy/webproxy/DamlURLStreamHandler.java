package org.cougaar.core.security.policy.webproxy;

import java.io.IOException;

import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

import org.cougaar.core.security.policy.webproxy.DamlURLConnection;

/**
 * 
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


  /*
   * This code selects either opens a connection using the regular web
   * client or using the daml client.
   */
  protected URLConnection openConnection(URL u)
    throws IOException
  {
    if (_log != null && _log.isDebugEnabled()) {
      _log.debug("Opening url " + u.toString());
    }
    if (u.toString().endsWith(".daml")) {
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
      }
      if (_log != null && _log.isDebugEnabled()) {
        _log.debug("Using original web client");
        _log.debug("++++++++++++++++++++++++++++++++++++++++++++++++");
      }
      return new sun.net.www.protocol.http.HttpURLConnection(u,
                                                             u.getHost(),
                                                             u.getPort());
    }
  }
}
