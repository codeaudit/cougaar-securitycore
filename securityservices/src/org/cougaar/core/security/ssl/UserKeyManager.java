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

import java.net.PasswordAuthentication;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.userauth.AuthenticationHandler;
import org.cougaar.core.security.userauth.CertAuthListener;

public final class UserKeyManager extends org.cougaar.core.security.ssl.KeyManager
  implements CertAuthListener
{
  // provides the default implementation, but it can be overwritten
  private AuthenticationHandler handler;

  /*
  // hash map from domain to alias
  private Hashtable domainTable;
  // hash map from alias to cert
  private Hashtable aliasTable;
  */

  protected X509Certificate userx509 = null;

  public UserKeyManager(KeyRingService krs, ServiceBroker sb) {
    super(krs, sb);
  }

  public void setPasswordAuthentication(PasswordAuthentication pa) {}

  public void setAuthHandler(AuthenticationHandler auth) {
    this.handler = auth;
    auth.setAuthListener(this);
  }

  public void setAlias(String alias) {
    nodealias = alias;
  }

  public void setPrivateKey(PrivateKey pkey) {
    privatekey = pkey;
  }

  public void setCertificate(X509Certificate cert) {
    userx509 = cert;
  }

  public synchronized void updateKeystore() {
  /*
    if (domainTable == null) {
      domainTable = new Hashtable();
      aliasTable = new Hashtable();
    }

    // update domain to alias map table
    domainTable.clear();
    aliasTable.clear();
    KeyStore ks = keyRing.getKeyStore();
    try {
      for (Enumeration e = ks.aliases(); e.hasMoreElements(); ) {
        String alias = (String)e.nextElement();
        X509Certificate usrcert = (X509Certificate)
          ks.getCertificate(alias);
        String attrib = usrcert.getSubjectDN().getName();
        if (!CertificateUtility.findAttribute(attrib, "t").equals(
          DirectoryKeyStore.CERT_TITLE_USER))
          continue;
        aliasTable.put(alias, usrcert);
      }
    } catch (KeyStoreException ksex) {
      ksex.printStackTrace();
    }
    */
  }

  public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    /*
    // get the domain and check if there is alias specified for access the domain
    synchronized (this) {
      String alias = null;

      if (socket != null) {
        InetAddress inetaddr = (InetAddress)socket.getInetAddress();
        String host = inetaddr.getHostName();
        if (log.isDebugEnabled())
          log.debug("Connecting to host: " + host);

        // match with the domain list
        alias = (String)domainTable.get(host);
      }

      // if no default alias prompt for user alias
      if (alias == null) {
        if (aliasTable.size() > 0)
          alias = userUI.chooseClientAlias(aliasTable);

      }
      return alias;
    }
    */
    if (nodealias == null && handler != null) {
      try {
        handler.authenticateUser(handler.getUserName());
      } catch (Exception ex) {}
    }

    return nodealias;
  }

  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    // user application has no server alias
    return null;
  }

  public X509Certificate[] getCertificateChain(String alias) {
    if (log.isDebugEnabled())
      log.debug("getCertificateChain: " + alias);

    //X509Certificate userx509 = (X509Certificate)aliasTable.get(alias);
    if (alias.equals(nodealias) && userx509 != null) {
      try {
        return keyRing.checkCertificateTrust(userx509);
      } catch (Exception e) {
        if (log.isWarnEnabled()) {
	  log.warn("Failed to check certificate trust of user certificate");
	}
      }
    }

    if (log.isWarnEnabled())
      log.warn("Failed to getCertificateChain");

    return new X509Certificate[] {};
  }

  public String[] getClientAliases(String keyType, Principal[] issuers) {
    // should not just return every user certificate, they should be protected
    // by different passwords
    return new String [] {};
  }

  public PrivateKey getPrivateKey(String alias) {
    if (log.isDebugEnabled())
      log.debug("getPrivateKey: " + alias);

      /*
    PrivateKey privatekey = null;

    // look for it in the
    String commonName = keystore.getCommonName(alias);
    if (commonName != null) {
      List privatekeyList = keyRing.findPrivateKey(commonName);
      privatekey = ((PrivateKeyCert)privatekeyList.get(0)).getPrivateKey();
    }

    // prompt for password if user certificate is locked
    // private key not in cert cache, then load it from the keystore
    if (privatekey == null) {
      // prompt until user cancel
      // may setup trial threshold here
      while (true) {
        String pkeypwd = userUI.getUserPassword(alias);
        if (pkeypwd == null) break;

        try {
          privatekey = (PrivateKey)keyRing.getKeyStore().getKey(alias, pkeypwd.toCharArray());
        } catch (Exception ex) {
          if (!(ex instanceof UnrecoverableKeyException))
            break;
        }
      }

      if (privatekey != null) {
        // install into certcache, but does not validate
        // later on the getCertificateChain will be called
        try {
          X509Certificate userx509 = (X509Certificate)
            keyRing.getKeyStore().getCertificate(alias);
          keystore.addCertificateToCache(alias, userx509, privatekey);
        } catch (KeyStoreException ksex) {}
      }
    }
    */
    return privatekey;
  }

  public String[] getServerAliases(String keyType, Principal[] issuers) {
    return new String [] {};
  }


}
