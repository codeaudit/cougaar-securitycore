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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.auth.ChainedPrincipal;
import org.cougaar.core.security.auth.StringPrincipal;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

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
    String name = null;
    Subject subject = (Subject) 
      AccessController.doPrivileged(new GetSubject(acc));
    Set set = null;
    if (subject == null) {
      if (_log.isInfoEnabled()) {
        _log.info("Unable to retrieve Subject data");
      }
      set = new HashSet(0);
    }
    else {
      set = subject.getPrincipals(ChainedPrincipal.class);
    }
    if (set.isEmpty()) {
      if(_log.isDebugEnabled()) {
        _log.debug("No principals available. Using node agent's");
      }
      name = NodeInfo.getNodeName();
    } else {
      // should only be one ChainedPrincipal
      ArrayList list = ((ChainedPrincipal)set.iterator().next()).getChain();
      if(list.size() == 0) {
        if(_log.isDebugEnabled()) {
          _log.debug("No ChainedPrincipals available. Using node agent's");
        }
        name = NodeInfo.getNodeName();
      } else {
        // if we get a ChainedPrincipal with node/agent/component, index should
        // be the agent.  if we get a node/component, index should be the node.
        int index = (list.size() >= 2 ? list.size() - 2 : 0);
        name = ((StringPrincipal)list.get(index)).getName();        
      }
    }
    if(_log.isDebugEnabled()) {
      _log.debug("Returning principal: " + name);
    }
    return name;
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
