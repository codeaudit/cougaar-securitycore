package org.cougaar.core.security.util;

import javax.net.ssl.*;
import javax.net.*;
import java.net.*;
import java.io.*;
import java.nio.channels.ServerSocketChannel;


public class DebugSSLServerSocket extends SSLServerSocketWrapper {
  private int _id = getID();
  private static int _sid = 1;

  private static synchronized int getID (){ return _sid++; };
    
  public DebugSSLServerSocket(ServerSocket socket) throws IOException {
    super(socket);
    System.out.println("" + _id +
                       "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= <init>: ");
  }

  public String[] getEnabledCipherSuites() {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getEnabledCipherSuites()");
    return super.getEnabledCipherSuites();
  }

  public String[] getEnabledProtocols() {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getEnabledProtocols");
    return super.getEnabledProtocols();
  }

  public boolean getEnableSessionCreation() {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getEnableSessionCreation");
    return super.getEnableSessionCreation();
  }

  public boolean getNeedClientAuth() {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getNeedClientAuth");
    return super.getNeedClientAuth();
  }

  public String[] getSupportedCipherSuites() {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSupportedCipherSuites");
    return super.getSupportedCipherSuites();
  }

  public String[] getSupportedProtocols() {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSupportedProtocols");
    return super.getSupportedProtocols();
  }
    
  public boolean getUseClientMode() {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getUseClientMode");
    return super.getUseClientMode();
  }

  public boolean getWantClientAuth() {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getWantClientAuth");
    return super.getWantClientAuth();
  }

  public void setEnabledCipherSuites(String[] suites) 
    throws IllegalArgumentException {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setEnabledCipherSuites");
    super.setEnabledCipherSuites(suites);
  }

  public void setEnabledProtocols(String[] protocols) 
    throws IllegalArgumentException {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setEnabledProtocols");
    super.setEnabledProtocols(protocols);
  }

  public void setEnableSessionCreation(boolean flag) {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setEnableSessionCreation");
    super.setEnableSessionCreation(flag);
  }

  public void setNeedClientAuth(boolean need) {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setNeedClientAuth");
    super.setNeedClientAuth(need);
  }

  public void setUseClientMode(boolean mode) 
    throws IllegalArgumentException {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setUseClientMode");
    super.setUseClientMode(mode);
  }

  public void setWantClientAuth(boolean want) {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setWantClientAuth");
    super.setWantClientAuth(want);
  }

  public void bind(SocketAddress bindpoint)
    throws IOException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= bind");
    super.bind(bindpoint);
  }

  public void bind(SocketAddress bindpoint, int backlog)
    throws IOException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= bind");
    super.bind(bindpoint, backlog);
  }

  public InetAddress getInetAddress() {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getInetAddress");
    return super.getInetAddress() ;
  }

  public int getLocalPort(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getLocalPort");
    return super.getLocalPort();
  }

  public SocketAddress getLocalSocketAddress(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getLocalSocketAddress");
    return super.getLocalSocketAddress();
  }

  public Socket accept()
    throws IOException {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= accept");
    return super.accept();
  }

  public void setSoTimeout(int timeout)
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setSoTimeout");
    super.setSoTimeout(timeout);
  }

  public int getSoTimeout()
    throws SocketException, IOException {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSoTimeout");
    return super.getSoTimeout();
  }

  public void setReceiveBufferSize(int size)
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setReceiveBufferSize");
    super.setReceiveBufferSize(size);
  }

  public int getReceiveBufferSize()
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getReceiveBufferSize");
    return super.getReceiveBufferSize();
  }

  public void setReuseAddress(boolean on)
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setReuseAddress");
    super.setReuseAddress(on);
  }

  public boolean getReuseAddress()
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getReuseAddress");
    return super.getReuseAddress();
  }

  public void close()
    throws IOException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= close");
    super.close();
  }

  public ServerSocketChannel getChannel() {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getChannel");
    return super.getChannel();
  }
    
  public String toString(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= toString");
    return super.toString();
  }

  public boolean isBound(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isBound");
    return super.isBound();
  }

  public boolean isClosed(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isClosed");
    return super.isClosed();
  }
}

