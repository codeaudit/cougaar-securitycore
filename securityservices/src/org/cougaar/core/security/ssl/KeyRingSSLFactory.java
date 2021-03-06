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

package org.cougaar.core.security.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

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

  private SSLSocketFactory _fact;
  private static SSLSocketCache   _socketCache;

  static {
    _socketCache = new SSLSocketCache();
  }

  /**
   * Default constructor.
   */
  protected KeyRingSSLFactory() {
    _fact = _ctx.getSocketFactory();
    _log = LoggerFactory.getInstance().createLogger(KeyRingSSLFactory.class);
  }

  protected KeyRingSSLFactory(SSLContext ctx) {
//    _socketCache = new SSLSocketCache();
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
	  _log.error("SSL Context is null. Crypto service not initialized properly", e);
	}
	else {
	  System.err.println("SSL Context is null. Crypto service not initialized properly");
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
    if (_log.isInfoEnabled()) {
      _log.info("Creating Client socket");
    }
    Socket socket = _fact.createSocket();
    updateSocketCache(socket);
    return socket;
//     return new DebugSSLSocket(_fact.createSocket());
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(Socket, String, int, boolean)
   */
  public Socket createSocket(Socket sock, String host, int port,
                             boolean autoClose) throws IOException {
    if (_log.isInfoEnabled()) {
      _log.info("Creating Client socket to " + host + ":" + port);
    }
    Socket socket = _fact.createSocket(sock,host,port,autoClose);
    updateSocketCache(socket);
    return socket;
//     return new DebugSSLSocket(_fact.createSocket(sock,host,port,autoClose));
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(InetAddress, int)
   */
  public Socket createSocket(InetAddress host, int port) throws IOException {
    if (_log.isInfoEnabled()) {
      _log.info("Creating Client socket to " + host + ":" + port);
    }
    Socket socket = _fact.createSocket(host,port);
    updateSocketCache(socket);
    return socket;
//     return new DebugSSLSocket(_fact.createSocket(host,port));
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(InetAddress, int, InetAddress, int)
   */
  public Socket createSocket(InetAddress host, int port,
                             InetAddress localAddress, int localPort)
    throws IOException {
    if (_log.isInfoEnabled()) {
      _log.info("Creating Client socket to " + host + ":" + port);
    }
    Socket socket = _fact.createSocket(host,port,localAddress,localPort);
    updateSocketCache(socket);
    return socket;
//     return new DebugSSLSocket(_fact.createSocket(host,port,localAddress,localPort));
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(String, int)
   */
  public Socket createSocket(String host, int port) throws IOException {
    if (_log.isInfoEnabled()) {
      _log.info("Creating Client socket to " + host + ":" + port);
    }
    Socket socket = _fact.createSocket(host,port);
    updateSocketCache(socket);
    return socket;
//     return new DebugSSLSocket(_fact.createSocket(host,port));
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(String, int, InetAddress, int)
   */
  public Socket createSocket(String host, int port,
                             InetAddress localAddress, int localPort)
    throws IOException {
    if (_log.isInfoEnabled()) {
      _log.info("Creating Client socket to " + host + ":" + port);
    }
    Socket socket = _fact.createSocket(host,port,localAddress,localPort);
    updateSocketCache(socket);
    return socket;
//     return new DebugSSLSocket(_fact.createSocket(host,port,localAddress,localPort));
  }

  private void updateSocketCache(Socket socket) 
    throws IOException
  {
    SSLSession session = null;
    // Adding a timeout to try to resolve bug 13600.
    // https://bugs.ultralog.net/show_bug.cgi?id=13600
    //    socket.setSoTimeout(5 * 60 * 1000);

    if (socket instanceof SSLSocket) {
      session = ((SSLSocket)socket).getSession();
    }
    if (session != null) {
      _socketCache.put(session, socket);
    }
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

  /** Provide the opportunity to invalidate existing or future
   *  SSL sessions that use a given certificate.
   */
  public static void invalidateSession(X509Certificate aCert) {
    _socketCache.closeSockets(aCert);
  }

}
