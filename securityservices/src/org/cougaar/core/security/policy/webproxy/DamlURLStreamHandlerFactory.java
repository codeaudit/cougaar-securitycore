package org.cougaar.core.security.policy.webproxy;

import java.io.PrintStream;

import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;

import org.cougaar.core.security.policy.webproxy.DamlURLStreamHandler;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;


/**
 * This is a factory that takes a protocol and generates a
 * URLStreamHandler.  The URLStreamHandler then takes a URL and
 * returns a URLConnection...
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
      sb.getService(new DamlURLStreamHandlerFactory(), LoggingService.class, null);
  }

  public URLStreamHandler createURLStreamHandler(String protocol) {
    if (_log != null && _log.isDebugEnabled()) {
      _log.debug("+++++++++++++++++++++++++++++++++++++++++++++++++");
      _log.debug("Protocol = " + protocol);
    }
    if (protocol.equals("http")) {
      //System.out.println("Returning the proxy handler")
      return new DamlURLStreamHandler();
    } else {
      if (_log != null && _log.isDebugEnabled()) {
        _log.debug("using the default handler");
      }
      return null;
    }
  }

}
