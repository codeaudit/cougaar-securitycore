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
