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

package org.cougaar.core.security.services.identity;

import org.cougaar.core.component.Service;

//import org.cougaar.lib.web.arch.server.*;
import javax.net.ServerSocketFactory;

public interface WebserverIdentityService extends Service {
  /**
   * This function should be called at Tomcat startup.
   * It will perform the following:
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

