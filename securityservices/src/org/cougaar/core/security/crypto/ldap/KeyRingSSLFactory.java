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
package org.cougaar.core.security.crypto.ldap;

import java.io.IOException;
import java.net.Socket;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import org.cougaar.core.security.services.crypto.KeyRingService;

/**
 * KeyRingSSLFactory provides a mechanism for JNDI to use the KeyRingService
 * for the KeyManager and TrustManager. The Node certificates are
 * used for client authentication if client authentication is requested.
 *
 * @see CertDirectoryService
 * @author George Mount <gmount@nai.com>
 */
public class KeyRingSSLFactory extends SocketFactory {
  static KeyRingSSLFactory _default;

  SSLSocketFactory         _fact;
  KeyManager               _km;
  TrustManager             _tm;
  KeyRingService           _krs;
  
  /**
   * Constructor requires a handle to the KeyRingService.
   */
  public KeyRingSSLFactory(KeyRingService krs) throws KeyManagementException {
    _krs = krs;
    _km = new NodeKeyManager(krs);
    _tm = new NodeTrustManager(krs);
    try {
      SSLContext ctx = SSLContext.getInstance("TLS");
      ctx.init(new KeyManager[] {_km}, new TrustManager[] {_tm}, null);
      _fact = ctx.getSocketFactory();
    } catch (NoSuchAlgorithmException ex) {
      // this should never happen! Dump to the console
      System.err.println("Could not load TLS services!");
      ex.printStackTrace();
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
      throw new IllegalStateException("KeyRingSSLFactory has not been initialized");
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
  public synchronized static void init(KeyRingService krs) {
    try {
      _default = new KeyRingSSLFactory(krs);
    } catch (KeyManagementException ex) {
      // there should never be a problem with the KeyRingService's keys!
      System.err.println("Problem with the KeyRingService's keys.");
      ex.printStackTrace();
    }
  }
}
