package org.cougaar.core.security.util;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.nio.channels.SocketChannel;

public class DebugSSLSocket extends SSLSocketWrapper {
  private int _id = getID();
  private static int _sid = 1;

  private static synchronized int getID () { return _sid++; };
    
  public DebugSSLSocket(Socket socket) {
    super(socket);
    System.out.println("" + _id +
                       "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= <init>: " +
                       socket.getRemoteSocketAddress());
  }

  public void addHandshakeCompletedListener(HandshakeCompletedListener listener) throws IllegalArgumentException {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= addHandshakeCompletedListener");
    super.addHandshakeCompletedListener(listener);
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

  public SSLSession getSession() {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSession");
    return super.getSession();
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

  public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) throws IllegalArgumentException {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= removeHandshakeCompletedListener");
    super.removeHandshakeCompletedListener(listener); 
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

  public void startHandshake() throws IOException {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= startHandshake");
    super.startHandshake();
  }

  public void connect(SocketAddress endpoint)
    throws IOException {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= connect");
    super.connect(endpoint);
  }

  public void connect(SocketAddress endpoint,
                      int timeout)
    throws IOException {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= connect");
    super.connect(endpoint, timeout);
  }

  public void bind(SocketAddress bindpoint)
    throws IOException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= bind");
    super.bind(bindpoint);
  }

  public InetAddress getInetAddress() {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getInetAddress");
    return super.getInetAddress() ;
  }

  public InetAddress getLocalAddress(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getLocalAddress");
    return super.getLocalAddress();
  }

  public int getPort(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getPort");
    return super.getPort();
  }

  public int getLocalPort(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getLocalPort");
    return super.getLocalPort();
  }

  public SocketAddress getRemoteSocketAddress(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getRemoteSocketAddress");
    return super.getRemoteSocketAddress();
  }

  public SocketAddress getLocalSocketAddress(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getLocalSocketAddress");
    return super.getLocalSocketAddress();
  }

  public SocketChannel getChannel(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getChannel");
    return super.getChannel();
  }

  public InputStream getInputStream()
    throws IOException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getInputStream");
    return super.getInputStream();
  }

  public OutputStream getOutputStream()
    throws IOException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getOutputStream");
    return super.getOutputStream();
  }

  public void setTcpNoDelay(boolean on)
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setTcpNoDelay");
    super.setTcpNoDelay(on);
  }

  public boolean getTcpNoDelay()
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getTcpNoDelay");
    return super.getTcpNoDelay();
  }

  public void setSoLinger(boolean on,
                          int linger)
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setSoLinger");
    super.setSoLinger(on, linger);
  }

  public int getSoLinger()
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSoLinger");
    return super.getSoLinger();
  }

  public void sendUrgentData(int data)
    throws IOException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= sendUrgentData");
    super.sendUrgentData(data);
  }

  public void setOOBInline(boolean on)
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setOOBInline");
    super.setOOBInline(on);
  }

  public boolean getOOBInline()
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getOOBInline");
    return super.getOOBInline();
  }

  public void setSoTimeout(int timeout)
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setSoTimeout");
    super.setSoTimeout(timeout);
  }

  public int getSoTimeout()
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSoTimeout");
    return super.getSoTimeout();
  }

  public void setSendBufferSize(int size)
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setSendBufferSize");
    super.setSendBufferSize(size);
  }

  public int getSendBufferSize()
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSendBufferSize");
    return super.getSendBufferSize();
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

  public void setKeepAlive(boolean on)
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setKeepAlive");
    super.setKeepAlive(on);
  }

  public boolean getKeepAlive()
    throws SocketException {
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getKeepAlive");
    return super.getKeepAlive();
  }

  public void setTrafficClass(int tc)
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setTrafficClass");
    super.setTrafficClass(tc);
  }

  public int getTrafficClass()
    throws SocketException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getTrafficClass");
    return super.getTrafficClass();
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

  public void shutdownInput()
    throws IOException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= shutdownInput");
    super.shutdownInput();
  }

  public void shutdownOutput()
    throws IOException{
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= shutdownOutput");
    super.shutdownOutput();
  }

  public String toString(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= toString");
    return super.toString();
  }

  public boolean isConnected(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isConnected");
    return super.isConnected();
  }

  public boolean isBound(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isBound");
    return super.isBound();
  }

  public boolean isClosed(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isClosed");
    return super.isClosed();
  }

  public boolean isInputShutdown(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isInputShutdown");
    return super.isInputShutdown();
  }

  public boolean isOutputShutdown(){
    System.out.println("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isOutputShutdown");
    return super.isOutputShutdown();
  }
}
