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

import javax.net.ssl.*;
import javax.net.*;
import java.net.*;
import java.io.IOException;

import org.cougaar.core.security.crypto.KeyRingPermission;

public class KeyRingSSLServerFactory extends SSLServerSocketFactory {
  private static KeyRingSSLServerFactory _default;
  private static SSLContext _sslcontext;

  SSLServerSocketFactory ssocfac;

  boolean needAuth = false;

  public void setNeedClientAuth(boolean needAuth) {
    this.needAuth = needAuth;
  }

  protected KeyRingSSLServerFactory(SSLContext sslcontext) {
    ssocfac = sslcontext.getServerSocketFactory();
  }

  protected KeyRingSSLServerFactory() {
    ssocfac = _sslcontext.getServerSocketFactory();
  }

  /**
   * Returns the default SSL server socket factory.
   */
  public synchronized static ServerSocketFactory getDefault() {
  /*
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("KeyRingSSLServerFactory.getDefault"));
    }
    */

    if (_default == null) {
      if (_sslcontext == null) {
        //System.out.println("SSLContext is NULL!");
        //return null;
        throw new RuntimeException("SSL context is null!");
      }
      _default = new KeyRingSSLServerFactory();
    }
    return _default;
  }

  public static ServerSocketFactory getInstance(SSLContext sslcontext) {
    return new KeyRingSSLServerFactory(sslcontext);
  }

  /**
   * Returns the list of cipher suites which are enabled by default.
   */
  public String[] getDefaultCipherSuites() {
    return ssocfac.getDefaultCipherSuites();
  }

  /**
   * Returns the names of the cipher suites which could be enabled for
   * use on an SSL connection created by this factory.
   */
  public String[] getSupportedCipherSuites() {
    return ssocfac.getSupportedCipherSuites();
  }

  /**
   * Returns an unbound server socket. The socket is configured with
   * the socket options (such as accept timeout) given to this factory.
   */
  public ServerSocket createServerSocket()
    throws IOException
  {
    return applySocketConstraints(ssocfac.createServerSocket());
  }

  public ServerSocket createServerSocket(int port)
    throws IOException
  {
    return applySocketConstraints(ssocfac.createServerSocket(port));
  }

  public ServerSocket createServerSocket(int port,
                                          int backlog)
    throws IOException
  {
    return applySocketConstraints(ssocfac.createServerSocket(port, backlog));
  }

  public ServerSocket createServerSocket(int port,
                                          int backlog,
                                          InetAddress ifAddress)
    throws IOException
  {
    return applySocketConstraints(ssocfac.createServerSocket(port, backlog, ifAddress));
  }

  private ServerSocket applySocketConstraints(ServerSocket soc) {
    if (needAuth)
      ((SSLServerSocket)soc).setNeedClientAuth(true);
    else
    // default is want client authentication
      ((SSLServerSocket)soc).setWantClientAuth(true);
    return soc;
  }

  public synchronized static void init(SSLContext sslcontext) {
    if (_sslcontext == null)
      _sslcontext = sslcontext;
  }
}
