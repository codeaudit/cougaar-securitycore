/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */

package org.cougaar.core.security.ssl;

import java.io.IOException;
import javax.net.ssl.*;
import java.net.*;
import javax.net.*;

import org.apache.catalina.net.*;

import org.cougaar.core.security.services.identity.*;

public class WebtomcatSSLServerFactory
  implements org.apache.catalina.net.ServerSocketFactory {

  protected static javax.net.ssl.SSLServerSocketFactory socfac = null;

  /**
   * Integrate into tomcat socket factory
   * Use socketfactory from securityservices
   */
  public WebtomcatSSLServerFactory(WebserverIdentityService webssl) {
      socfac = (javax.net.ssl.SSLServerSocketFactory)
        webssl.getWebServerSocketFactory();
  }

  // all the keystore related functions will not be supported

    // --------------------------------------------------------- Public Methods

    public ServerSocket createSocket(int port) throws IOException {
        return socfac.createServerSocket(port);
    }


    public ServerSocket createSocket(int port, int backlog)
        throws IOException {
        return socfac.createServerSocket(port, backlog);
    }

    public ServerSocket createSocket(int port, int backlog,
                                     InetAddress ifAddress)
        throws IOException {
        return socfac.createServerSocket(port, backlog, ifAddress);
    }


}