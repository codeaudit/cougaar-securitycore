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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.PrivateKeyCert;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.Subject;

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
  //DirectoryKeyStore        _dirKeystore;
  LoggingService           _log;

  /**
   * Default constructor.
   */
  public JaasSSLFactory(KeyRingService krs, ServiceBroker sb) {
    _krs = krs;
    _sb  = sb;
    //  _dirKeystore = _krs.getDirectoryKeyStore();
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
	
        List l =null;
	if(_krs!=null){
	 l= _krs.findPrivateKey(name);
	}
        if (l == null || l.isEmpty()) {
          _log.info("Couldn't find private key for " + name + 
                    " when creating SSLSocketFactory");
	  name = "-- no client certificate -- ";
	  fact = (SSLSocketFactory) _factories.get(name);
	  if (fact != null) {
	    return fact;
	  }
        } else {
          PrivateKeyCert pkc = (PrivateKeyCert) l.get(0);
          km.setPrivateKey(pkc.getPrivateKey());
	  if(_krs!=null){
	  km.setAlias(_krs.findAlias(name));
	  l = _krs.findCert(name, KeyRingService.LOOKUP_LDAP | 
				    KeyRingService.LOOKUP_KEYSTORE);
	  }
	  if (l == null || l.isEmpty()) {
	    _log.warn("Couldn't find certificate for " + name + 
		      " when creating SSLSocketFactory");
	  } else {
	    CertificateStatus certStatus = (CertificateStatus) l.get(0);
	    km.setCertificate((X509Certificate) certStatus.getCertificate());
	  }
        } 
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
    if (subject == null || subject.getPrincipals() == null) {
      _log.info("No principals available. Using node agent's");
    } else {
      Iterator it = subject.getPrincipals().iterator(); 
      while (it.hasNext()) {
        Principal p = (Principal) it.next();
        // Do not use (p instanceof ChainedPrincipal) as 
        // the class may have been loaded by a different class loader.
        if (p.getClass().getName().
            equals("org.cougaar.core.security.securebootstrap.StringPrincipal")) {
        }
        try {
          Class c = p.getClass();
          Method m = c.getDeclaredMethod("getName", null);
          return (String) m.invoke(p, null);
        }
        catch (Exception e) {
          _log.error("Unable to get principal: " + e);
        }
      }
      _log.error("Unable to get principal. Using NodeInfo.getNodeName()");
    }
    return NodeInfo.getNodeName();

    /*
    Set set = subject.getPrincipals(StringPrincipal.class);
    if (set.isEmpty()) {
      return NodeInfo.getNodeName();
    } // end of if (set.isEmpty())
 
    return ((StringPrincipal)set.iterator().next()).getName();
    */
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
