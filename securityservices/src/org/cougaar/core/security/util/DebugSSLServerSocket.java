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

import javax.net.ssl.*;
import javax.net.*;
import java.net.*;
import java.io.*;
import java.nio.channels.ServerSocketChannel;

import org.cougaar.core.service.LoggingService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class DebugSSLServerSocket extends SSLServerSocketWrapper {
  private int _id = getID();
  private static int _sid = 1;
  private static Logger _log;

  static {
    _log = LoggerFactory.getInstance().createLogger("DebugSSLServerSocket");
  }

  private static synchronized int getID (){ return _sid++; };
    
  public DebugSSLServerSocket(ServerSocket socket) throws IOException {
    super(socket);
    _log.debug("" + _id +
                       "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* <init>: ");
  }

  public String[] getEnabledCipherSuites() {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getEnabledCipherSuites()");
    return super.getEnabledCipherSuites();
  }

  public String[] getEnabledProtocols() {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getEnabledProtocols");
    return super.getEnabledProtocols();
  }

  public boolean getEnableSessionCreation() {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getEnableSessionCreation");
    return super.getEnableSessionCreation();
  }

  public boolean getNeedClientAuth() {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getNeedClientAuth");
    return super.getNeedClientAuth();
  }

  public String[] getSupportedCipherSuites() {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getSupportedCipherSuites");
    return super.getSupportedCipherSuites();
  }

  public String[] getSupportedProtocols() {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getSupportedProtocols");
    return super.getSupportedProtocols();
  }
    
  public boolean getUseClientMode() {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getUseClientMode");
    return super.getUseClientMode();
  }

  public boolean getWantClientAuth() {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getWantClientAuth");
    return super.getWantClientAuth();
  }

  public void setEnabledCipherSuites(String[] suites) 
    throws IllegalArgumentException {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* setEnabledCipherSuites");
    super.setEnabledCipherSuites(suites);
  }

  public void setEnabledProtocols(String[] protocols) 
    throws IllegalArgumentException {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* setEnabledProtocols");
    super.setEnabledProtocols(protocols);
  }

  public void setEnableSessionCreation(boolean flag) {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* setEnableSessionCreation");
    super.setEnableSessionCreation(flag);
  }

  public void setNeedClientAuth(boolean need) {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* setNeedClientAuth");
    super.setNeedClientAuth(need);
  }

  public void setUseClientMode(boolean mode) 
    throws IllegalArgumentException {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* setUseClientMode");
    super.setUseClientMode(mode);
  }

  public void setWantClientAuth(boolean want) {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* setWantClientAuth");
    super.setWantClientAuth(want);
  }

  public void bind(SocketAddress bindpoint)
    throws IOException{
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* bind");
    super.bind(bindpoint);
  }

  public void bind(SocketAddress bindpoint, int backlog)
    throws IOException{
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* bind");
    super.bind(bindpoint, backlog);
  }

  public InetAddress getInetAddress() {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getInetAddress");
    return super.getInetAddress() ;
  }

  public int getLocalPort(){
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getLocalPort");
    return super.getLocalPort();
  }

  public SocketAddress getLocalSocketAddress(){
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getLocalSocketAddress");
    return super.getLocalSocketAddress();
  }

  public Socket accept()
    throws IOException {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* accept");
    return super.accept();
  }

  public void setSoTimeout(int timeout)
    throws SocketException{
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* setSoTimeout");
    super.setSoTimeout(timeout);
  }

  public int getSoTimeout()
    throws SocketException, IOException {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getSoTimeout");
    return super.getSoTimeout();
  }

  public void setReceiveBufferSize(int size)
    throws SocketException{
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* setReceiveBufferSize");
    super.setReceiveBufferSize(size);
  }

  public int getReceiveBufferSize()
    throws SocketException{
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getReceiveBufferSize");
    return super.getReceiveBufferSize();
  }

  public void setReuseAddress(boolean on)
    throws SocketException{
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* setReuseAddress");
    super.setReuseAddress(on);
  }

  public boolean getReuseAddress()
    throws SocketException{
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getReuseAddress");
    return super.getReuseAddress();
  }

  public void close()
    throws IOException{
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* close");
    super.close();
  }

  public ServerSocketChannel getChannel() {
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* getChannel");
    return super.getChannel();
  }
    
  public String toString(){
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* toString");
    return super.toString();
  }

  public boolean isBound(){
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* isBound");
    return super.isBound();
  }

  public boolean isClosed(){
    _log.debug("" + _id + "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-* isClosed");
    return super.isClosed();
  }
}

