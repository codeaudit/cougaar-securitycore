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


package org.cougaar.core.security.services.identity;

import org.cougaar.core.security.services.crypto.SSLService;

import javax.net.ServerSocketFactory;

public interface WebserverIdentityService extends SSLService {
  /**
   * This function should be called at Tomcat startup, it will
   * perform the following:
   *
   * 1. check whether there is a certificate for tomcat server, if not get one
   * 2. check whether the server cert has expired, if so get one
   * 3. initialize SSLContext with our own keystore and truststore
   * 4. return a catalina SSLServerSocketFactory instance
   *
   * The SSLServerSocketFactory is either a subclass of catalina.SSLServerSocketFactory
   * or the catalina factory itself, with context settings using SecurityServices'
   * keystore and trust store.
   *
   * If there is no certificate available, a factory will still be returned,
   * but the creation of SSLServerSocket will find no cert in keystore and will fail.
   *
   */
  ServerSocketFactory getWebServerSocketFactory();

  /**
   * This function is to set HttpsConfig parameters, Cougaar may have its own
   * config policy requirements.
   *
   * @parameter:    the HttpsConfig passed from Tomcat configuration
   * @return:       the modified HttpsConfig, could change keystore, keystore password,
   *                etc.
   *
   */

  /**
   * HttpsConfig exists in the cougaar tomcat make path
   * but not the securityservices make path.
   **/
  //HttpsConfig setHttpsConfig(HttpsConfig httpsC);
}

