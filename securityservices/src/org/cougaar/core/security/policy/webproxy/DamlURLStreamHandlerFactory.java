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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;


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
