/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

package org.cougaar.core.security.util;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

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

public class DebugSSLSocket extends SSLSocketWrapper {
  private int _id = getID();
  private static int _sid = 1;

  private static Logger _log;

  static {
    _log = LoggerFactory.getInstance().createLogger("DebugSSLSocket");
  }

  private static synchronized int getID () { return _sid++; };
    
  public DebugSSLSocket(Socket socket) {
    super(socket);
    _log.debug("" + _id +
                       "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= <init>: " +
                       socket.getLocalSocketAddress() + " -> " +
                       socket.getRemoteSocketAddress());
  }

  public void addHandshakeCompletedListener(HandshakeCompletedListener listener) throws IllegalArgumentException {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= addHandshakeCompletedListener");
    super.addHandshakeCompletedListener(listener);
  }
    
  public String[] getEnabledCipherSuites() {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getEnabledCipherSuites()");
    return super.getEnabledCipherSuites();
  }

  public String[] getEnabledProtocols() {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getEnabledProtocols");
    return super.getEnabledProtocols();
  }

  public boolean getEnableSessionCreation() {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getEnableSessionCreation");
    return super.getEnableSessionCreation();
  }

  public boolean getNeedClientAuth() {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getNeedClientAuth");
    return super.getNeedClientAuth();
  }

  public SSLSession getSession() {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSession");
    return super.getSession();
  }

  public String[] getSupportedCipherSuites() {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSupportedCipherSuites");
    return super.getSupportedCipherSuites();
  }

  public String[] getSupportedProtocols() {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSupportedProtocols");
    return super.getSupportedProtocols();
  }
    
  public boolean getUseClientMode() {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getUseClientMode");
    return super.getUseClientMode();
  }

  public boolean getWantClientAuth() {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getWantClientAuth");
    return super.getWantClientAuth();
  }

  public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) throws IllegalArgumentException {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= removeHandshakeCompletedListener");
    super.removeHandshakeCompletedListener(listener); 
  }

  public void setEnabledCipherSuites(String[] suites) 
    throws IllegalArgumentException {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setEnabledCipherSuites");
    super.setEnabledCipherSuites(suites);
  }

  public void setEnabledProtocols(String[] protocols) 
    throws IllegalArgumentException {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setEnabledProtocols");
    super.setEnabledProtocols(protocols);
  }

  public void setEnableSessionCreation(boolean flag) {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setEnableSessionCreation");
    super.setEnableSessionCreation(flag);
  }

  public void setNeedClientAuth(boolean need) {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setNeedClientAuth");
    super.setNeedClientAuth(need);
  }

  public void setUseClientMode(boolean mode) 
    throws IllegalArgumentException {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setUseClientMode");
    super.setUseClientMode(mode);
  }

  public void setWantClientAuth(boolean want) {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setWantClientAuth");
    super.setWantClientAuth(want);
  }

  public void startHandshake() throws IOException {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= startHandshake");
    super.startHandshake();
  }

  public void connect(SocketAddress endpoint)
    throws IOException {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= connect");
    super.connect(endpoint);
  }

  public void connect(SocketAddress endpoint,
                      int timeout)
    throws IOException {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= connect");
    super.connect(endpoint, timeout);
  }

  public void bind(SocketAddress bindpoint)
    throws IOException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= bind");
    super.bind(bindpoint);
  }

  public InetAddress getInetAddress() {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getInetAddress");
    return super.getInetAddress() ;
  }

  public InetAddress getLocalAddress(){
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getLocalAddress");
    return super.getLocalAddress();
  }

  public int getPort(){
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getPort");
    return super.getPort();
  }

  public int getLocalPort(){
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getLocalPort");
    return super.getLocalPort();
  }

  public SocketAddress getRemoteSocketAddress(){
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getRemoteSocketAddress");
    return super.getRemoteSocketAddress();
  }

  public SocketAddress getLocalSocketAddress(){
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getLocalSocketAddress");
    return super.getLocalSocketAddress();
  }

  public SocketChannel getChannel(){
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getChannel");
    return super.getChannel();
  }

  public InputStream getInputStream()
    throws IOException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getInputStream");
    return super.getInputStream();
  }

  public OutputStream getOutputStream()
    throws IOException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getOutputStream");
    return super.getOutputStream();
  }

  public void setTcpNoDelay(boolean on)
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setTcpNoDelay: " + on);
    super.setTcpNoDelay(on);
  }

  public boolean getTcpNoDelay()
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getTcpNoDelay");
    return super.getTcpNoDelay();
  }

  public void setSoLinger(boolean on,
                          int linger)
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setSoLinger");
    super.setSoLinger(on, linger);
  }

  public int getSoLinger()
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSoLinger");
    return super.getSoLinger();
  }

  public void sendUrgentData(int data)
    throws IOException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= sendUrgentData");
    super.sendUrgentData(data);
  }

  public void setOOBInline(boolean on)
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setOOBInline");
    super.setOOBInline(on);
  }

  public boolean getOOBInline()
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getOOBInline");
    return super.getOOBInline();
  }

  public void setSoTimeout(int timeout)
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setSoTimeout");
    super.setSoTimeout(timeout);
  }

  public int getSoTimeout()
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSoTimeout");
    return super.getSoTimeout();
  }

  public void setSendBufferSize(int size)
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setSendBufferSize");
    super.setSendBufferSize(size);
  }

  public int getSendBufferSize()
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getSendBufferSize");
    return super.getSendBufferSize();
  }

  public void setReceiveBufferSize(int size)
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setReceiveBufferSize");
    super.setReceiveBufferSize(size);
  }

  public int getReceiveBufferSize()
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getReceiveBufferSize");
    return super.getReceiveBufferSize();
  }

  public void setKeepAlive(boolean on)
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setKeepAlive");
    super.setKeepAlive(on);
  }

  public boolean getKeepAlive()
    throws SocketException {
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getKeepAlive");
    return super.getKeepAlive();
  }

  public void setTrafficClass(int tc)
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setTrafficClass");
    super.setTrafficClass(tc);
  }

  public int getTrafficClass()
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getTrafficClass");
    return super.getTrafficClass();
  }

  public void setReuseAddress(boolean on)
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= setReuseAddress");
    super.setReuseAddress(on);
  }

  public boolean getReuseAddress()
    throws SocketException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= getReuseAddress");
    return super.getReuseAddress();
  }

  public void close()
    throws IOException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= close");
    super.close();
  }

  public void shutdownInput()
    throws IOException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= shutdownInput");
    super.shutdownInput();
  }

  public void shutdownOutput()
    throws IOException{
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= shutdownOutput");
    super.shutdownOutput();
  }

  public String toString(){
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= toString");
    return super.toString();
  }

  public boolean isConnected(){
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isConnected");
    return super.isConnected();
  }

  public boolean isBound(){
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isBound");
    return super.isBound();
  }

  public boolean isClosed(){
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isClosed");
    return super.isClosed();
  }

  public boolean isInputShutdown(){
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isInputShutdown");
    return super.isInputShutdown();
  }

  public boolean isOutputShutdown(){
    _log.debug("" + _id + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= isOutputShutdown");
    return super.isOutputShutdown();
  }
}
