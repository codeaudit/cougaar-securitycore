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
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.util.NodeInfo;

import java.net.Socket;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public final class ServerKeyManager
  extends org.cougaar.core.security.ssl.KeyManager {
  public ServerKeyManager(KeyRingService krs, ServiceBroker sb)
    throws CertificateException
  {
    super(krs, sb);

    if (nodex509 == null || nodealias == null) {
      log.warn("No valid server certificate");
      throw new CertificateException("No valid server certificate.");
    }
  }

  public synchronized void updateKeystore() {
  /*
    // find the valid hostname, get key alias and server certificate
    // use nodealias to set server alias which is the hostname
    String hostname = getName();
    nodename = hostname;

    //log.debug("=====> getHostName: " + hostname);

    // node will generate host certificate
    //keyRing.checkOrMakeCert(hostname);

    List nodex509List = keyRing.findCert(hostname);
    if (nodex509List != null && nodex509List.size() > 0) {
      nodex509 = ((CertificateStatus)nodex509List.get(0)).getCertificate();
    }
    nodealias = keystore.findAlias(hostname);
    */
    super.updateKeystore();

    // no valid certificate? Use self signed cert
    if (nodealias != null && privatekey == null) {
      if (log.isDebugEnabled()) {
        log.debug("No valid server cert, retrieving self sign host cert.");
      }

      CertificateCacheService cacheservice=(CertificateCacheService)
	serviceBroker.getService(this,
				 CertificateCacheService.class,
				 null);
      if(cacheservice==null) {
	log.warn(" Unable to get Certificate Cache service in updateKeystore");
      }
      try {

        nodex509 = null;
	if(cacheservice!=null) {
	  nodex509=cacheservice.getCertificate(nodealias);
          privatekey=cacheservice.getKey(nodealias);
	}
        // No need to get private key, it is not required to
        // start server, only cert and trusted chain are.
        //privatekey = (PrivateKey)keystore.getKeyStore().getKey(nodealias, new char[] {});
        if (nodex509 != null)
          certChain = new X509Certificate [] {nodex509};
      } catch (Exception kex) {
        if (log.isDebugEnabled())
          log.debug("Cannot retrieve server's self-signed cert. " + kex);
      }
    }

    if (log.isDebugEnabled())
      log.debug("WeberserverSSLContext:KeyManager: nodealias is " + nodealias
			 + " and nodex509 is " + nodex509);
  }

  public String chooseClientAlias(String keyType, Principal[] issuers, Socket socket) {
    // server application has no client alias
    return null;
  }

  public String[] getClientAliases(String keyType, Principal[] issuers) {
    return new String [] {};
  }

  public String getName() {
    return NodeInfo.getHostName();
  }

  static boolean _managerReady = false;
  protected void setManagerReady() {
    _managerReady = true;
  }

  public static boolean isManagerReady() {
    return _managerReady;
  }
}
