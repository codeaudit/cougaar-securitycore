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

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.cert.CertificateException;

import org.cougaar.core.security.services.identity.WebserverIdentityService;

public class WebtomcatSSLServerFactory
  implements org.apache.catalina.net.ServerSocketFactory {

  protected static javax.net.ssl.SSLServerSocketFactory socfac = null;
  protected static boolean needAuth = false;

  public void setNeedClientAuth(boolean needClientAuth) {
    needAuth = needClientAuth;
  }

  /**
   * Integrate into tomcat socket factory
   * Use socketfactory from securityservices
   */
  public WebtomcatSSLServerFactory()
    throws CertificateException {
    // check permission

    // if not initialized throws runtime exception
    if (socfac == null) {
      throw new CertificateException("SSL socket factory is not initialized.");
    }
  }

  public synchronized static void init(WebserverIdentityService webssl) {
    socfac = (javax.net.ssl.SSLServerSocketFactory)
      webssl.getWebServerSocketFactory();
    ((KeyRingSSLServerFactory)socfac).setNeedClientAuth(needAuth);
  }

  // all the keystore related functions will not be supported
  // --------------------------------------------------------- Public Methods

  public ServerSocket createSocket(int port) throws IOException {
    return socfac.createServerSocket(port);
  }


  public ServerSocket createSocket(int port, int backlog)
    throws IOException {
    return socfac.createServerSocket(port, backlog);
  }

  public ServerSocket createSocket(int port, int backlog,
				   InetAddress ifAddress)
    throws IOException {
    return socfac.createServerSocket(port, backlog, ifAddress);
  }
}
