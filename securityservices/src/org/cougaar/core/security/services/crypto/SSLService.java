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

package org.cougaar.core.security.services.crypto;

import org.cougaar.core.component.Service;

public interface SSLService extends Service {
  /**
   * Notify SSLService to update certficates from keystore
   * Initially Node has no certificate, once Node obtains
   * certificate should notify SSLService. Otherwise SSL
   * communication will be disabled.
   */
  public void updateKeystore();

  /**
   * The RMISocketFactory subclasses should use the
   * SSL factories instantiated from this service,
   * instead of using the default JSSE implementation.
   *
   * This function will also set the per-class HttpsURLConnection
   * SSLSocketFactory so that any URL/URLConnection/HttpURLConnection
   * and HttpsURLConnection instances already created
   * or will be created will be using the socket factories
   * instantiated here.
   */
   /*
  public ServerSocketFactory getServerSocketFactory();

  public SocketFactory getSocketFactory();
  */

  /**
   * The sockets created with the two functions above
   * needs to specify port and host.
   * This function searches the appropriate port for the
   * agent or node, then creates the socket with the port.
   *
   * @param       name of agent / node
   * @exception   IOException, unable to establish connection
   * @exception   certificate corresponding with the specified
   *              agentName is invalid/untrusted/etc.
   *
   * This functions will not be implemented unless we decide to
   * support agent peer-to-peer communication
   */
   /*
  public SSLServerSocket createServerSocket(String agentName)
	throws IOException, CertificateException;

  public SSLSocket createSocket(String targetAgent, String agentName)
        throws IOException, CertificateException;
        */

}

