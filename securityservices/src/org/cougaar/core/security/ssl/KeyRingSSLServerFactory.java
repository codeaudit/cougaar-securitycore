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

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;
import org.cougaar.core.security.util.SSLServerSocketWrapper;
import org.cougaar.core.security.util.SSLSocketWrapper;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.WeakHashMap;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;

public class KeyRingSSLServerFactory extends SSLServerSocketFactory {
  private static KeyRingSSLServerFactory _default;
  private static SSLContext _sslcontext;
  private static WeakHashMap _sessionMap = new WeakHashMap();
  private static Logger _log = LoggerFactory.getInstance().createLogger(KeyRingSSLServerFactory.class);

  private static SSLSocketCache   _socketCache;

  static {
    _socketCache = new SSLSocketCache();
  }

  SSLServerSocketFactory ssocfac;

  boolean needAuth = true;
  static final HandshakeCompletedListener HANDSHAKE_LISTENER = 
    new HandshakeCompletedListener() {
      public void handshakeCompleted(HandshakeCompletedEvent event) {
        updateSocketCache(event.getSocket());
      }
    };

  public static Principal getPrincipal() {
    synchronized (_sessionMap) {
      return (Principal) _sessionMap.get(Thread.currentThread());
    }
  }

  private static void setPrincipal(SSLSocket socket) {
    if (_log.isDebugEnabled()) {
      _log.debug("Entering setPrincipal");
    }
    java.security.cert.Certificate[] peer = null;
    try {
      SSLSession session = socket.getSession();
      if (session != null) {
        _log.debug("Have a session");
        peer = session.getPeerCertificates();
        if (_log.isDebugEnabled()) {
          _log.debug("peer = " + peer);
        }
        if (peer != null && peer.length > 0 &&
            peer[0] instanceof X509Certificate) {
          X509Certificate cert = (X509Certificate) peer[0];
          synchronized (_sessionMap) {
            _sessionMap.put(Thread.currentThread(),cert.getSubjectDN());
            if (_log.isDebugEnabled()) {
              _log.debug("Setting principal for " + Thread.currentThread()
                         + " to " + cert.getSubjectDN());
            }
          }
        } else {
          if (_log.isDebugEnabled()) {
            _log.debug("No peer certificate!");
          }
        }
      } else {
        if (_log.isDebugEnabled()) {
          _log.debug("No SSL Session!");
        }
      }
    } catch (SSLPeerUnverifiedException e) {
      // don't set anything, there is no peer
      if (_log.isDebugEnabled()) {
        _log.debug("Problem Setting principal for " 
                   + Thread.currentThread()
                   + ", ", e);

        _log.debug("peer = " + peer);
      }
    }
  }

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
    if (_log.isInfoEnabled()) {
      _log.info("Creating Server socket");
    }
    return applySocketConstraints(new WrappedSSLServerSocket(ssocfac.createServerSocket()));
  }

  public ServerSocket createServerSocket(int port)
    throws IOException
  {
    if (_log.isInfoEnabled()) {
      _log.info("Creating Server socket on port = " + port);
    }
    return applySocketConstraints(new WrappedSSLServerSocket(ssocfac.createServerSocket(port)));
  }

  public ServerSocket createServerSocket(int port,
                                          int backlog)
    throws IOException
  {
    if (_log.isInfoEnabled()) {
      _log.info("Creating Server socket on port = " + port);
    }
    return applySocketConstraints(new WrappedSSLServerSocket(ssocfac.createServerSocket(port, backlog)));
  }

  public ServerSocket createServerSocket(int port,
                                          int backlog,
                                          InetAddress ifAddress)
    throws IOException
  {
    if (_log.isInfoEnabled()) {
      _log.info("Creating Server socket on port = " + port + " and interface "+ ifAddress);
    }
    return applySocketConstraints(new WrappedSSLServerSocket(ssocfac.createServerSocket(port, backlog, ifAddress)));
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

  private static final class WrappedSSLServerSocket 
    extends SSLServerSocketWrapper {

    public WrappedSSLServerSocket(ServerSocket socket) throws IOException {
      super(socket);
      if (_log.isInfoEnabled()){
        _log.info("Port actually obtained = " + socket.getLocalPort());
      }
    }

    public Socket accept()
      throws IOException {
      Socket sock = super.accept();
      if (sock == null) {
        return sock;
      }
      SSLSocket sslSocket = (SSLSocket) sock;
      sslSocket.addHandshakeCompletedListener(HANDSHAKE_LISTENER);
      return new WrappedSSLSocket(sslSocket);
    }
  }

  private static final class WrappedSSLSocket extends SSLSocketWrapper {
    public WrappedSSLSocket(Socket socket) {
      super(socket);
    }
    
    public InputStream getInputStream()
      throws IOException{
      setPrincipal(_socket);

      return super.getInputStream();
    }
  }
  
  private static void updateSocketCache(Socket socket) {
    SSLSession session = null;
    if (socket instanceof SSLSocket) {
      session = ((SSLSocket)socket).getSession();
    }
    if (session != null) {
      _socketCache.put(session, socket);
    }
  }

  /** Provide the opportunity to invalidate existing or future
   *  SSL sessions that use a given certificate.
   */
  public static void invalidateSession(X509Certificate aCert) {
    _socketCache.closeSockets(aCert);
  }
}
