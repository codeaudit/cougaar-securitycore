package org.cougaar.core.security.ssl;

import javax.net.ssl.*;
import javax.net.*;
import java.net.*;
import java.io.IOException;

public class KeyRingSSLServerFactory extends SSLServerSocketFactory {
  private static KeyRingSSLServerFactory _default;
  private static SSLContext _sslcontext;

  SSLServerSocketFactory ssocfac;

  private KeyRingSSLServerFactory() {
    if (_sslcontext == null)
      System.out.println("SSLContext is NULL!");
    else
      ssocfac = _sslcontext.getServerSocketFactory();
  }

  /**
   * Returns the default SSL server socket factory.
   */
  public synchronized static ServerSocketFactory getDefault() {
    if (_default == null)
      _default = new KeyRingSSLServerFactory();
    return _default;
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
    // default is want client authentication
    ((SSLServerSocket)soc).setWantClientAuth(true);
    return soc;
  }

  public synchronized static void init(SSLContext sslcontext) {
    if (_sslcontext == null)
      _sslcontext = sslcontext;
    else
      System.out.println("SSLContext already set!");
  }
}