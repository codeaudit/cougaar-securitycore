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

import java.util.HashMap;
import java.util.Set;
import java.util.List;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.InetAddress;
import java.nio.channels.SocketChannel;
import java.security.PrivilegedAction;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;


import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.HandshakeCompletedListener;
import javax.security.auth.Subject;

import org.cougaar.core.security.securebootstrap.StringPrincipal;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.security.crypto.DirectoryKeyStore;
import org.cougaar.core.service.LoggingService;

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
public class JaasSSLFactory extends SSLSocketFactory {
  HashMap                  _factories = new HashMap();
  TrustManager             _trustManager;
  ServiceBroker            _sb;
  KeyRingService           _krs;
  DirectoryKeyStore        _dirKeystore;
  LoggingService           _log;

  /**
   * Default constructor.
   */
  public JaasSSLFactory(KeyRingService krs, ServiceBroker sb) {
    _krs = krs;
    _sb  = sb;
    _dirKeystore = _krs.getDirectoryKeyStore();
    _log = (LoggingService)
      _sb.getService(this,LoggingService.class, null);
    _trustManager = new TrustManager(_krs, sb);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket()
   */
  public Socket createSocket() throws IOException {
    return getFactory().createSocket();
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(Socket, String, int, boolean)
   */
  public Socket createSocket(Socket sock, String host, int port,
                             boolean autoClose) throws IOException {
    return getFactory().createSocket(sock,host,port,autoClose);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(InetAddress, int)
   */
  public Socket createSocket(InetAddress host, int port) throws IOException {
    return getFactory().createSocket(host,port);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(InetAddress, int, InetAddress, int)
   */
  public Socket createSocket(InetAddress host, int port,
                             InetAddress localAddress, int localPort)
    throws IOException {
    return getFactory().createSocket(host,port,localAddress,localPort);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(String, int)
   */
  public Socket createSocket(String host, int port) throws IOException {
    return getFactory().createSocket(host,port);
  }

  /**
   * Creates an <code>SSLSocket</code>
   *
   * @see javax.net.ssl.SSLSocketFactory#createSocket(String, int, InetAddress, int)
   */
  public Socket createSocket(String host, int port,
                             InetAddress localAddress, int localPort)
    throws IOException {
    return getFactory().createSocket(host,port,localAddress,localPort);
  }

  /**
   * Returns the default cipher suites
   *
   * @see javax.net.ssl.SSLSocketFactory#getDefaultCipherSuites()
   */
  public String[] getDefaultCipherSuites() {
    return getFactory().getDefaultCipherSuites();
  }

  /**
   * Returns the supported cipher suites
   *
   * @see javax.net.ssl.SSLSocketFactory#getSupportedCipherSuites()
   */
  public String[] getSupportedCipherSuites() {
    return getFactory().getSupportedCipherSuites();
  }

  private synchronized SSLSocketFactory getFactory() {
    String name = getName();
    SSLSocketFactory fact = (SSLSocketFactory) _factories.get(name);
    if (fact == null) {
      try {
        SSLContext context = SSLContext.getInstance("TLS");
        
        // create keymanager and trust manager
        UserKeyManager km = new UserKeyManager(_krs, _sb);
        km.setAlias(_dirKeystore.findAlias(name));
        List l = _dirKeystore.findPrivateKey(name);
        if (l.isEmpty()) {
          _log.warn("Couldn't find private key for " + name + 
                    " when creating SSLSocketFactory");
        } else {
          km.setPrivateKey((PrivateKey) l.get(0));
        } // end of else

        l = _dirKeystore.findCert(name, KeyRingService.LOOKUP_LDAP | 
                                  KeyRingService.LOOKUP_KEYSTORE);
        if (l.isEmpty()) {
          _log.warn("Couldn't find certificate for " + name + 
                    " when creating SSLSocketFactory");
        } else {
          km.setCertificate((X509Certificate) l.get(0));
        } // end of else
        
        context.init(new KeyManager[] {km}, 
                     new TrustManager[] {_trustManager}, null);
        
        fact = new KeyRingSSLFactory(context);
        _factories.put(name, fact);
      } catch (KeyManagementException e) {
        _log.error("Could not create SSL factory ", e);
      } catch (NoSuchAlgorithmException e) {
        _log.error("Could not create SSL factory for TLS", e);
      } // end of try-catch
      
    } // end of if (fact == null)
    return fact;
  }

  private String getName() {
    AccessControlContext acc = AccessController.getContext();
    Subject subject = (Subject) 
      AccessController.doPrivileged(new GetSubject(acc));
    Set set = subject.getPrincipals(StringPrincipal.class);
    if (set.isEmpty()) {
      return NodeInfo.getNodeName();
    } // end of if (set.isEmpty())
    
    return ((StringPrincipal)set.iterator().next()).getName();
  }

  private static class GetSubject implements PrivilegedAction {
    AccessControlContext _acc;

    public GetSubject(AccessControlContext acc) {
      _acc = acc;
    }

    public Object run() {
      return Subject.getSubject(_acc);
    }
  }

}
