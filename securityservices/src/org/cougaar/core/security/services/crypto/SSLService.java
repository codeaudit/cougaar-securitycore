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

