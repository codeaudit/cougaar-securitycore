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
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

/**
 * JNDISSLFactory provides a mechanism for JNDI to supply special SSL
 * arguments for its connection to the LDAP server. Normal SSL is possible
 * to use by setting <code>Context.SECURITY_PROTOCOL</code> to "ssl"
 * in the environment constructor parameter. However, special client
 * certificates and truststores cannot be specified separately from the
 * System environment. By initializing this class with the SSLContext
 * that is needed and passing 
 * "org.cougaar.core.security.crypto.ldap.JNDISSLFactory" as the
 * "java.naming.ldap.factory.socket" constructor environment parameter.
 * Note that this mechanism is <b>not</b> thread safe! You must ensure that
 * only one thread accesses the JNDISSLFactory for init and creation of
 * InitialDirContext at a time.
 *
 * @see SecureJNDIRealm
 * @author George Mount <gmount@nai.com>
 */
public class JNDISSLFactory extends SocketFactory {
  static JNDISSLFactory _default;
  static SSLContext   _ctx;
  SSLSocketFactory    _fact;

  /**
   * Default constructor.
   */
  public JNDISSLFactory() {
    _fact = _ctx.getSocketFactory();
  }

  /**
   * returns the default <code>SocketFactory</code>. This function is used by
   * InitialDirContext to get the <code>SocketFactory</code> object from the
   * class.
   *
   * @see #init
   */
  public synchronized static SocketFactory getDefault() {
    if (_default == null) {
      _default = new JNDISSLFactory();
    }
    return _default;
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory
   */
  public Socket createSocket() throws IOException {
    return _fact.createSocket();
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory
   */
  public Socket createSocket(Socket sock, String host, int port,
                             boolean autoClose) throws IOException {
    return _fact.createSocket(sock,host,port,autoClose);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory
   */
  public Socket createSocket(InetAddress host, int port) throws IOException {
    return _fact.createSocket(host,port);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory
   */
  public Socket createSocket(InetAddress host, int port,
                             InetAddress localAddress, int localPort) 
    throws IOException {
    return _fact.createSocket(host,port,localAddress,localPort);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory
   */
  public Socket createSocket(String host, int port) throws IOException {
    return _fact.createSocket(host,port);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory
   */
  public Socket createSocket(String host, int port, 
                             InetAddress localAddress, int localPort) 
    throws IOException {
    return _fact.createSocket(host,port,localAddress,localPort);
  }

  /**
   * Returns the default cipher suites
   *
   * @see javax.net.ssl.SSLSocketFactory
   */
  public String[] getDefaultCipherSuites() {
    return _fact.getDefaultCipherSuites();
  }

  /**
   * Returns the supported cipher suites
   *
   * @see javax.net.ssl.SSLSocketFactory
   */
  public String[] getSupportedCipherSuites() {
    return _fact.getSupportedCipherSuites();
  }

  /**
   * Initializes the class so that the default SocketFactory to
   * use the context provided. 
   *
   * @see #getDefault
   */
  public synchronized static void init(SSLContext ctx) {
    _ctx = ctx;
    _default = null;
  }
}
