package org.cougaar.core.security.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class SSLSocketWrapper extends SSLSocket {
  protected SSLSocket _socket;
  public SSLSocketWrapper(Socket socket) {
    _socket = (SSLSocket) socket;
  }

  public void addHandshakeCompletedListener(HandshakeCompletedListener listener) throws IllegalArgumentException {
    _socket.addHandshakeCompletedListener(listener);
  }
    
  public String[] getEnabledCipherSuites() {
    return _socket.getEnabledCipherSuites();
  }

  public String[] getEnabledProtocols() {
    return _socket.getEnabledProtocols();
  }

  public boolean getEnableSessionCreation() {
    return _socket.getEnableSessionCreation();
  }

  public boolean getNeedClientAuth() {
    return _socket.getNeedClientAuth();
  }

  public SSLSession getSession() {
    return _socket.getSession();
  }

  public String[] getSupportedCipherSuites() {
    return _socket.getSupportedCipherSuites();
  }

  public String[] getSupportedProtocols() {
    return _socket.getSupportedProtocols();
  }
    
  public boolean getUseClientMode() {
    return _socket.getUseClientMode();
  }

  public boolean getWantClientAuth() {
    return _socket.getWantClientAuth();
  }

  public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) throws IllegalArgumentException {
    _socket.removeHandshakeCompletedListener(listener); 
  }

  public void setEnabledCipherSuites(String[] suites) 
    throws IllegalArgumentException {
    _socket.setEnabledCipherSuites(suites);
  }

  public void setEnabledProtocols(String[] protocols) 
    throws IllegalArgumentException {
    _socket.setEnabledProtocols(protocols);
  }

  public void setEnableSessionCreation(boolean flag) {
    _socket.setEnableSessionCreation(flag);
  }

  public void setNeedClientAuth(boolean need) {
    _socket.setNeedClientAuth(need);
  }

  public void setUseClientMode(boolean mode) 
    throws IllegalArgumentException {
    _socket.setUseClientMode(mode);
  }

  public void setWantClientAuth(boolean want) {
    _socket.setWantClientAuth(want);
  }

  public void startHandshake() throws IOException {
    _socket.startHandshake();
  }

  public void bind(SocketAddress bindpoint)
    throws IOException{
    _socket.bind(bindpoint);
  }

  public void close()
    throws IOException{
    _socket.close();
  }

  public void connect(SocketAddress endpoint)
    throws IOException {
    _socket.connect(endpoint);
  }

  public void connect(SocketAddress endpoint,
                      int timeout)
    throws IOException {
    _socket.connect(endpoint, timeout);
  }

  public SocketChannel getChannel(){
    return _socket.getChannel();
  }

  public InetAddress getInetAddress() {
    return _socket.getInetAddress() ;
  }

  public InputStream getInputStream()
    throws IOException{
    return _socket.getInputStream();
  }

  public boolean getKeepAlive()
    throws SocketException {
    return _socket.getKeepAlive();
  }

  public InetAddress getLocalAddress(){
    return _socket.getLocalAddress();
  }

  public int getLocalPort(){
    return _socket.getLocalPort();
  }

  public SocketAddress getLocalSocketAddress(){
    return _socket.getLocalSocketAddress();
  }

  public boolean getOOBInline()
    throws SocketException{
    return _socket.getOOBInline();
  }

  public OutputStream getOutputStream()
    throws IOException{
    return _socket.getOutputStream();
  }

  public int getPort(){
    return _socket.getPort();
  }

  public int getReceiveBufferSize()
    throws SocketException{
    return _socket.getReceiveBufferSize();
  }

  public SocketAddress getRemoteSocketAddress(){
    return _socket.getRemoteSocketAddress();
  }

  public boolean getReuseAddress()
    throws SocketException{
    return _socket.getReuseAddress();
  }

  public int getSendBufferSize()
    throws SocketException{
    return _socket.getSendBufferSize();
  }

  public int getSoLinger()
    throws SocketException{
    return _socket.getSoLinger();
  }

  public int getSoTimeout()
    throws SocketException{
    return _socket.getSoTimeout();
  }

  public boolean getTcpNoDelay()
    throws SocketException{
    return _socket.getTcpNoDelay();
  }

  public int getTrafficClass()
    throws SocketException{
    return _socket.getTrafficClass();
  }

  public boolean isBound(){
    return _socket.isBound();
  }

  public boolean isClosed(){
    return _socket.isClosed();
  }

  public boolean isConnected(){
    return _socket.isConnected();
  }

  public boolean isInputShutdown(){
    return _socket.isInputShutdown();
  }

  public boolean isOutputShutdown(){
    return _socket.isOutputShutdown();
  }

  public void sendUrgentData(int data)
    throws IOException{
    _socket.sendUrgentData(data);
  }

  public void setKeepAlive(boolean on)
    throws SocketException{
    _socket.setKeepAlive(on);
  }

  public void setOOBInline(boolean on)
    throws SocketException{
    _socket.setOOBInline(on);
  }

  public void setReceiveBufferSize(int size)
    throws SocketException{
    _socket.setReceiveBufferSize(size);
  }

  public void setReuseAddress(boolean on)
    throws SocketException{
    _socket.setReuseAddress(on);
  }

  public void setSendBufferSize(int size)
    throws SocketException{
    _socket.setSendBufferSize(size);
  }

  public void setSoLinger(boolean on,
                          int linger)
    throws SocketException{
    _socket.setSoLinger(on, linger);
  }

  public void setSoTimeout(int timeout)
    throws SocketException{
    _socket.setSoTimeout(timeout);
  }

  public void setTcpNoDelay(boolean on)
    throws SocketException{
    _socket.setTcpNoDelay(on);
  }

  public void setTrafficClass(int tc)
    throws SocketException{
    _socket.setTrafficClass(tc);
  }

  public void shutdownInput()
    throws IOException{
    _socket.shutdownInput();
  }

  public void shutdownOutput()
    throws IOException{
    _socket.shutdownOutput();
  }

  public String toString(){
    return _socket.toString();
  }

  public int hashCode() {
    return _socket.hashCode();
  }
}
