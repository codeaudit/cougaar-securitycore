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
import java.net.Socket;
import java.net.InetAddress;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

// Cougaar core services
import org.cougaar.util.log.*;

// Cougaar security services
import org.cougaar.core.security.services.crypto.KeyRingService;

/**
 * KeyRingSSLFactory provides a mechanism for JNDI to use the KeyRingService
 * for the KeyManager and TrustManager. The Node certificates are
 * used for client authentication if client authentication is requested.
 *
 * @author George Mount <gmount@nai.com>
 */
public class KeyRingSSLFactory extends SSLSocketFactory {
  static KeyRingSSLFactory _default;
  static SSLContext        _ctx;
  static Logger            _log;

  SSLSocketFactory         _fact;
  /**
   * Default constructor.
   */
  protected KeyRingSSLFactory() {
    _fact = _ctx.getSocketFactory();
    _log = LoggerFactory.getInstance().createLogger(KeyRingSSLFactory.class);
  }

  protected KeyRingSSLFactory(SSLContext ctx) {
    _fact = ctx.getSocketFactory();
    _log = LoggerFactory.getInstance().createLogger(KeyRingSSLFactory.class);
  }

  /**
   * returns the default <code>SocketFactory</code>. This function is used by
   * InitialDirContext to get the <code>SocketFactory</code> object from the
   * class.
   *
   * @see #init(SSLContext ctx)
   */
  public synchronized static SocketFactory getDefault() {
    if (_default == null) {
      if (_ctx == null) {
	RuntimeException e = new RuntimeException("SSL Context is null");
	if (_log != null) {
	  _log.error("SSL Context is null", e);
	}
	else {
	  System.err.println("SSL Context is null");
	  e.printStackTrace();
	}
        throw e;
      }
      _default = new KeyRingSSLFactory();
    }
    return _default;
  }

  public static SocketFactory getInstance(SSLContext ctx) {
    return new KeyRingSSLFactory(ctx);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket()
   */
  public Socket createSocket() throws IOException {
    return _fact.createSocket();
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(Socket, String, int, boolean)
   */
  public Socket createSocket(Socket sock, String host, int port,
                             boolean autoClose) throws IOException {
    return _fact.createSocket(sock,host,port,autoClose);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(InetAddress, int)
   */
  public Socket createSocket(InetAddress host, int port) throws IOException {
    return _fact.createSocket(host,port);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(InetAddress, int, InetAddress, int)
   */
  public Socket createSocket(InetAddress host, int port,
                             InetAddress localAddress, int localPort)
    throws IOException {
    return _fact.createSocket(host,port,localAddress,localPort);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(String, int)
   */
  public Socket createSocket(String host, int port) throws IOException {
    return _fact.createSocket(host,port);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(String, int, InetAddress, int)
   */
  public Socket createSocket(String host, int port,
                             InetAddress localAddress, int localPort)
    throws IOException {
    return _fact.createSocket(host,port,localAddress,localPort);
  }

  /**
   * Returns the default cipher suites
   *
   * @see javax.net.ssl.SSLSocketFactory#getDefaultCipherSuites()
   */
  public String[] getDefaultCipherSuites() {
    return _fact.getDefaultCipherSuites();
  }

  /**
   * Returns the supported cipher suites
   *
   * @see javax.net.ssl.SSLSocketFactory#getSupportedCipherSuites()
   */
  public String[] getSupportedCipherSuites() {
    return _fact.getSupportedCipherSuites();
  }

  /**
   * Initializes the class so that the SocketFactory
   * so that it uses the KeyRingService provided
   *
   * @see #getDefault()
   */
  public synchronized static void init(SSLContext ctx) {
    if (_ctx == null)
      _ctx = ctx;
    else {
      //System.out.println("SSLContext is already set!");
      return;
    }
  }
}
