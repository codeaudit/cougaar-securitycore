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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.InetAddress;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.HandshakeCompletedListener;
import java.nio.channels.SocketChannel;


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
    return _fact.createSocket();
//     return new WrapSSLSocket(_fact.createSocket());
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(Socket, String, int, boolean)
   */
  public Socket createSocket(Socket sock, String host, int port,
                             boolean autoClose) throws IOException {
    return _fact.createSocket(sock,host,port,autoClose);
//     return new WrapSSLSocket(_fact.createSocket(sock,host,port,autoClose));
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(InetAddress, int)
   */
  public Socket createSocket(InetAddress host, int port) throws IOException {
    return _fact.createSocket(host,port);
//     return new WrapSSLSocket(_fact.createSocket(host,port));
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
//     return new WrapSSLSocket(_fact.createSocket(host,port,localAddress,localPort));
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(String, int)
   */
  public Socket createSocket(String host, int port) throws IOException {
    return _fact.createSocket(host,port);
//     return new WrapSSLSocket(_fact.createSocket(host,port));
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
//     return new WrapSSLSocket(_fact.createSocket(host,port,localAddress,localPort));
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

  private static final class WrapSSLSocket extends SSLSocket {
    private SSLSocket _socket;
    private int _id = getID();
    private static int _sid = 1;

    private static synchronized int getID (){ return _sid++; };
    
    public WrapSSLSocket(Socket socket) {
      _socket = (SSLSocket) socket;
      System.out.println("" + _id +
                         "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= <init>: " +
                         _socket.getRemoteSocketAddress());
    }

    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) throws IllegalArgumentException {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= addHandshakeCompletedListener");
      _socket.addHandshakeCompletedListener(listener);
    }
    
    public String[] getEnabledCipherSuites() {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getEnabledCipherSuites()");
      return _socket.getEnabledCipherSuites();
    }

    public String[] getEnabledProtocols() {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getEnabledProtocols");
      return _socket.getEnabledProtocols();
    }

    public boolean getEnableSessionCreation() {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getEnableSessionCreation");
      return _socket.getEnableSessionCreation();
    }

    public boolean getNeedClientAuth() {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getNeedClientAuth");
      return _socket.getNeedClientAuth();
    }

    public SSLSession getSession() {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSession");
      return _socket.getSession();
    }

    public String[] getSupportedCipherSuites() {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSupportedCipherSuites");
      return _socket.getSupportedCipherSuites();
    }

    public String[] getSupportedProtocols() {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSupportedProtocols");
      return _socket.getSupportedProtocols();
    }
    
    public boolean getUseClientMode() {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getUseClientMode");
      return _socket.getUseClientMode();
    }

    public boolean getWantClientAuth() {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getWantClientAuth");
      return _socket.getWantClientAuth();
    }

    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) throws IllegalArgumentException {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= removeHandshakeCompletedListener");
      _socket.removeHandshakeCompletedListener(listener); 
    }

    public void setEnabledCipherSuites(String[] suites) 
      throws IllegalArgumentException {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setEnabledCipherSuites");
      _socket.setEnabledCipherSuites(suites);
    }

    public void setEnabledProtocols(String[] protocols) 
      throws IllegalArgumentException {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setEnabledProtocols");
      _socket.setEnabledProtocols(protocols);
    }

    public void setEnableSessionCreation(boolean flag) {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setEnableSessionCreation");
      _socket.setEnableSessionCreation(flag);
    }

    public void setNeedClientAuth(boolean need) {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setNeedClientAuth");
      _socket.setNeedClientAuth(need);
    }

    public void setUseClientMode(boolean mode) 
      throws IllegalArgumentException {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setUseClientMode");
      _socket.setUseClientMode(mode);
    }

    public void setWantClientAuth(boolean want) {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setWantClientAuth");
      _socket.setWantClientAuth(want);
    }

    public void startHandshake() throws IOException {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= startHandshake");
      _socket.startHandshake();
    }

    public void connect(SocketAddress endpoint)
      throws IOException {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= connect");
      _socket.connect(endpoint);
    }

    public void connect(SocketAddress endpoint,
                        int timeout)
      throws IOException {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= connect");
      _socket.connect(endpoint, timeout);
    }

    public void bind(SocketAddress bindpoint)
      throws IOException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= bind");
      _socket.bind(bindpoint);
    }

    public InetAddress getInetAddress() {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getInetAddress");
      return _socket.getInetAddress() ;
    }

    public InetAddress getLocalAddress(){
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getLocalAddress");
      return _socket.getLocalAddress();
    }

    public int getPort(){
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getPort");
      return _socket.getPort();
    }

    public int getLocalPort(){
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getLocalPort");
      return _socket.getLocalPort();
    }

    public SocketAddress getRemoteSocketAddress(){
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getRemoteSocketAddress");
      return _socket.getRemoteSocketAddress();
    }

    public SocketAddress getLocalSocketAddress(){
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getLocalSocketAddress");
      return _socket.getLocalSocketAddress();
    }

    public SocketChannel getChannel(){
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getChannel");
      return _socket.getChannel();
    }

    public InputStream getInputStream()
      throws IOException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getInputStream");
      return _socket.getInputStream();
    }

    public OutputStream getOutputStream()
      throws IOException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getOutputStream");
//       return _socket.getOutputStream();
      return new WrapOutputStream(_socket.getOutputStream());
    }

    public void setTcpNoDelay(boolean on)
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setTcpNoDelay");
      _socket.setTcpNoDelay(on);
    }

    public boolean getTcpNoDelay()
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getTcpNoDelay");
      return _socket.getTcpNoDelay();
    }

    public void setSoLinger(boolean on,
                            int linger)
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setSoLinger");
      _socket.setSoLinger(on, linger);
    }

    public int getSoLinger()
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSoLinger");
      return _socket.getSoLinger();
    }

    public void sendUrgentData(int data)
      throws IOException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= sendUrgentData");
      _socket.sendUrgentData(data);
    }

    public void setOOBInline(boolean on)
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setOOBInline");
      _socket.setOOBInline(on);
    }

    public boolean getOOBInline()
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getOOBInline");
      return _socket.getOOBInline();
    }

    public void setSoTimeout(int timeout)
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setSoTimeout");
      _socket.setSoTimeout(timeout);
    }

    public int getSoTimeout()
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSoTimeout");
      return _socket.getSoTimeout();
    }

    public void setSendBufferSize(int size)
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setSendBufferSize");
      _socket.setSendBufferSize(size);
    }

    public int getSendBufferSize()
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSendBufferSize");
      return _socket.getSendBufferSize();
    }

    public void setReceiveBufferSize(int size)
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setReceiveBufferSize");
      _socket.setReceiveBufferSize(size);
    }

    public int getReceiveBufferSize()
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getReceiveBufferSize");
      return _socket.getReceiveBufferSize();
    }

    public void setKeepAlive(boolean on)
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setKeepAlive");
      _socket.setKeepAlive(on);
    }

    public boolean getKeepAlive()
      throws SocketException {
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getKeepAlive");
      return _socket.getKeepAlive();
    }

    public void setTrafficClass(int tc)
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setTrafficClass");
      _socket.setTrafficClass(tc);
    }

    public int getTrafficClass()
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getTrafficClass");
      return _socket.getTrafficClass();
    }

    public void setReuseAddress(boolean on)
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setReuseAddress");
      _socket.setReuseAddress(on);
    }

    public boolean getReuseAddress()
      throws SocketException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getReuseAddress");
      return _socket.getReuseAddress();
    }

    public void close()
      throws IOException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= close");
      _socket.close();
    }

    public void shutdownInput()
      throws IOException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= shutdownInput");
      _socket.shutdownInput();
    }

    public void shutdownOutput()
      throws IOException{
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= shutdownOutput");
      _socket.shutdownOutput();
    }

    public String toString(){
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= toString");
      return _socket.toString();
    }

    public boolean isConnected(){
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isConnected");
      return _socket.isConnected();
    }

    public boolean isBound(){
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isBound");
      return _socket.isBound();
    }

    public boolean isClosed(){
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isClosed");
      return _socket.isClosed();
    }

    public boolean isInputShutdown(){
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isInputShutdown");
      return _socket.isInputShutdown();
    }

    public boolean isOutputShutdown(){
      System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isOutputShutdown");
      return _socket.isOutputShutdown();
    }

    private static final class WrapOutputStream extends OutputStream {
      private OutputStream _out;

      public WrapOutputStream(OutputStream out) {
        _out = out;
      }
      
      public void write(int b)
        throws IOException {
        System.out.println("1*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 write byte");
                           
        _out.write(b);
      }

      public void write(byte[] b)
        throws IOException {
        System.out.println("2*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 write " +
                           b.length + " bytes");
        _out.write(b);
        printBytes(b,0,b.length);
      }


      public void write(byte[] b,
                        int off,
                        int len)
        throws IOException{
        System.out.println("3*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 write " +
                           len + " bytes");
        _out.write(b,off,len);
        printBytes(b,off,len);
      }


      public void flush()
        throws IOException{
        System.out.println("4*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 flush");
        _out.flush();
      }


      public void close()
        throws IOException{
        System.out.println("5*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 close");
        _out.close();
      }

      private static void printBytes(byte[] b, int start, int len) {
        char[] hex = { '0','1','2','3','4','5','6','7',
                       '8','9','A','B','C','D','E','F' };
        for (int i = start; i < start + len; i++) {
          int highNibble = (b[i] & 0xF0) >> 4;
          int lowNibble  = (b[i] & 0x0F);
          if ((i - start) % 16 == 0) {
            int b1 = ((i - start) & 0xF000) >> 12;
            int b2 = ((i - start) & 0x0F00) >>  8;
            int b3 = ((i - start) & 0x00F0) >>  4;
            int b4 = ((i - start) & 0x000F);
            System.out.print("\n" + hex[b1] + hex[b2] + 
                             hex[b3] + hex[b4] + ":");
          } else if ((i - start) % 8 == 0) {
            System.out.print("  ");
          } 
          System.out.print(" " + hex[highNibble] + hex[lowNibble]);
        } // end of for (int i = start; i < start + len; i++)
        System.out.println();
      }
    }
  }

}
