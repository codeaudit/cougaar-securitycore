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
import java.io.Serializable;
import java.net.Socket;
import java.net.InetAddress;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.cougaar.core.security.services.crypto.KeyRingService;

/**
 * KeyRingSSLFactory provides a mechanism for JNDI to use the KeyRingService
 * for the KeyManager and TrustManager. The Node certificates are
 * used for client authentication if client authentication is requested.
 *
 * @see CertDirectoryService
 * @author George Mount <gmount@nai.com>
 */
public class KeyRingSSLFactory extends SSLSocketFactory {
  static KeyRingSSLFactory _default;
  static SSLContext        _ctx;

  SSLSocketFactory         _fact;
  /**
   * Default constructor.
   */
  public KeyRingSSLFactory() {

    if (_ctx == null) {
      System.out.println("Context is null!!!!");
    } else {
      _fact = _ctx.getSocketFactory();
    }
  }

  /**
   * returns the default <code>SocketFactory</code>. This function is used by
   * InitialDirContext to get the <code>SocketFactory</code> object from the
   * class.
   *
   * @see init
   */
  public synchronized static SocketFactory getDefault() {
    if (_default == null) {
      _default = new KeyRingSSLFactory();
    }
    return _default;
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.SSLSocketFactory
   */
  public Socket createSocket() throws IOException {
    return _fact.createSocket();
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.SSLSocketFactory
   */
  public Socket createSocket(Socket sock, String host, int port,
                             boolean autoClose) throws IOException {
    return _fact.createSocket(sock,host,port,autoClose);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.SSLSocketFactory
   */
  public Socket createSocket(InetAddress host, int port) throws IOException {
    return _fact.createSocket(host,port);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.SSLSocketFactory
   */
  public Socket createSocket(InetAddress host, int port,
                             InetAddress localAddress, int localPort)
    throws IOException {
    return _fact.createSocket(host,port,localAddress,localPort);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.SSLSocketFactory
   */
  public Socket createSocket(String host, int port) throws IOException {
    return _fact.createSocket(host,port);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.SSLSocketFactory
   */
  public Socket createSocket(String host, int port,
                             InetAddress localAddress, int localPort)
    throws IOException {
    return _fact.createSocket(host,port,localAddress,localPort);
  }

  /**
   * Returns the default cipher suites
   *
   * @see javax.net.SSLSocketFactory
   */
  public String[] getDefaultCipherSuites() {
    return _fact.getDefaultCipherSuites();
  }

  /**
   * Returns the supported cipher suites
   *
   * @see javax.net.SSLSocketFactory
   */
  public String[] getSupportedCipherSuites() {
    return _fact.getSupportedCipherSuites();
  }

  /**
   * Initializes the class so that the SocketFactory
   * so that it uses the KeyRingService provided
   *
   * @see getDefault
   */
  public synchronized static void init(SSLContext ctx) {
    if (_ctx == null)
      _ctx = ctx;
    else
      System.out.println("SSLContext already set!");
  }
}
